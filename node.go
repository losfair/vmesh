package vnet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/losfair/vnet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	peer2 "google.golang.org/grpc/peer"
	"io/ioutil"
	"log"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const RetryDelay = 10 * time.Second
const RouteTimeout = 1 * time.Minute

type Node struct {
	Config    *NodeConfig
	CAPool    *x509.CertPool // Internal CA
	CA        *x509.Certificate
	PeerCerts PeerCertCollection // External Peers' certificates
	FullCert  tls.Certificate
	LocalID   PeerID
	Domain    string

	// Values of the `Peers` map can be temporarily nil to indicate a peer is being initialized.
	Peers sync.Map // PeerID -> *Peer

	RoutingTable LikeRoutingTable

	Vif Vif

	DCState DistributedConfigState
}

type PeerCertCollection struct {
	Certs map[PeerID]*x509.Certificate
}

type RouteInfo struct {
	Route        *protocol.Route
	NextPeerID   PeerID
	TotalLatency uint64
	UpdateTime   time.Time
}

type NodeConfig struct {
	ListenAddr            string       `json:"listen_addr"`
	CAPath                string       `json:"ca"`
	ExternalPeerCertPaths []string     `json:"external_peer_certs"`
	CertPath              string       `json:"cert"`
	PrivateKeyPath        string       `json:"private_key"`
	ServerName            string       `json:"server_name"`
	LocalAnnouncements    []string     `json:"local_announcements"`
	Peers                 []PeerConfig `json:"peers"`
	VifType               string       `json:"vif_type"`
	VifName               string       `json:"vif_name"`
}

type DistributedConfigState struct {
	sync.Mutex
	updateTime time.Time
	Config     *DistributedConfig
	RawConfig  *protocol.DistributedConfig

	PrefixWhitelistTable map[string]*LikeRoutingTable
}

func (s *DistributedConfigState) PrefixIsWhitelisted(name string, prefix [16]byte, prefixLen uint8) bool {
	s.Lock()
	table, ok := s.PrefixWhitelistTable[name]
	s.Unlock()

	// Allow by default if no entry is found in whitelist
	if !ok {
		return true
	}

	found := false

	_ = table.Lookup(prefix, prefixLen, func(_ [16]byte, _ uint8, _ interface{}) bool {
		found = true
		return false
	})

	return found
}

func (s *DistributedConfigState) updatePrefixWhitelistTableLocked() {
	s.PrefixWhitelistTable = make(map[string]*LikeRoutingTable)

	for name, allowed := range s.Config.PrefixWhitelist {
		table := &LikeRoutingTable{}
		for _, elem := range allowed {
			if err := table.InsertCIDR(elem, struct{}{}); err != nil {
				log.Println("failed to insert CIDR-format network into whitelist:", err)
			}
		}
		s.PrefixWhitelistTable[name] = table
	}
}

type DistributedConfig struct {
	PrefixWhitelist map[string][]string `json:"prefix_whitelist"` // node **name** -> list of allowed prefixes
}

type PeerConfig struct {
	Addr string `json:"addr"`
	Name string `json:"name"`
}

func NewNode(config *NodeConfig) (*Node, error) {
	fullCert, err := tls.LoadX509KeyPair(config.CertPath, config.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	if len(fullCert.Certificate) == 0 {
		return nil, errors.New("no certificate")
	}

	if fullCert.Leaf, err = x509.ParseCertificate(fullCert.Certificate[0]); err != nil {
		return nil, errors.New("cannot parse local certificate")
	}

	// The primary/internal CA
	caPool := x509.NewCertPool()
	caRaw, err := ioutil.ReadFile(config.CAPath)
	if err != nil {
		return nil, err
	}
	caPem, _ := pem.Decode(caRaw)
	if caPem == nil {
		return nil, errors.New("pem decoding failed")
	}
	ca, err := x509.ParseCertificate(caPem.Bytes)
	if err != nil {
		return nil, err
	}
	caPool.AddCert(ca)

	// External peers
	peerCerts := PeerCertCollection{Certs: make(map[PeerID]*x509.Certificate)}
	for _, alt := range config.ExternalPeerCertPaths {
		raw, err := ioutil.ReadFile(alt)
		if err != nil {
			return nil, fmt.Errorf("failed to read peer certificate at %s: %+v", alt, err)
		}

		certPem, _ := pem.Decode(raw)
		if certPem == nil {
			return nil, errors.New("pem decoding failed")
		}
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			return nil, err
		}

		certID := peerIDFromCertificate(cert)
		peerCerts.Certs[certID] = cert
	}

	var vif Vif
	switch config.VifType {
	case "tun":
		newVif, err := NewTun(config.VifName)
		if err != nil {
			return nil, err
		}
		vif = newVif
	case "dummy", "":
		vif = (*DummyVif)(nil)
	default:
		return nil, errors.New("invalid vif type")
	}

	domainParts := strings.SplitN(fullCert.Leaf.Subject.CommonName, ".", 2)
	if len(domainParts) != 2 {
		return nil, errors.New("invalid common name")
	}

	n := &Node{
		Config:    config,
		CAPool:    caPool,
		CA:        ca,
		PeerCerts: peerCerts,
		FullCert:  fullCert,
		LocalID:   peerIDFromCertificate(fullCert.Leaf),
		Domain:    domainParts[1],
		Vif:       vif,
		DCState: DistributedConfigState{
			PrefixWhitelistTable: make(map[string]*LikeRoutingTable),
		},
	}

	log.Println("Virtual interface:", vif.GetName())
	log.Printf("Local ID: %x\n", n.LocalID)
	log.Println("Domain:", n.Domain)
	log.Println("Local name:", n.FullCert.Leaf.Subject.CommonName)

	if len(config.LocalAnnouncements) > 0 {
		for _, ann := range config.LocalAnnouncements {
			_, ipnet, err := net.ParseCIDR(ann)
			if err != nil {
				return nil, err
			}

			if len(ipnet.IP) != 16 {
				return nil, errors.New("invalid ip prefix")
			}

			prefixLen, _ := ipnet.Mask.Size()
			var prefix [16]byte

			copy(prefix[:], ipnet.IP)
			if err := n.RoutingTable.Insert(prefix, uint8(prefixLen), RouteInfo{
				Route: &protocol.Route{
					Prefix:       ipnet.IP.Mask(ipnet.Mask),
					PrefixLength: uint32(prefixLen),
				},
				TotalLatency: 0,
			}); err != nil {
				return nil, err
			}
		}
	}

	return n, nil
}

func (n *Node) BuildPrintableRoutingTable() string {
	routes := make([]string, 0)

	n.RoutingTable.Range(func(prefix [16]byte, prefixLen uint8, _info interface{}) bool {
		info := _info.(RouteInfo)
		prettyPath := strings.Builder{}
		for _, item := range info.Route.Path {
			prettyPath.WriteString(fmt.Sprintf("    %x (Latency: %d)\n", item.Id, item.Latency))
		}
		routes = append(
			routes,
			fmt.Sprintf("ROUTE: %s/%d\n  Latency: %d\n  Path:\n%s", net.IP(info.Route.Prefix), info.Route.PrefixLength, info.TotalLatency, prettyPath.String()),
		)
		return true
	})
	sort.Strings(routes)
	return strings.Join(routes, "\n")
}

func (n *Node) UpdateDistributedConfig(dc *protocol.DistributedConfig) error {
	if dc.Version != 1 {
		return errors.New("unsupported distributed config version")
	}

	cert, err := x509.ParseCertificate(dc.Certificate)
	if err != nil {
		return errors.New("cannot parse certificate for DC")
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots: n.CAPool,
	})
	if err != nil {
		return errors.New("cannot verify certificate for DC")
	}

	if len(cert.URIs) != 1 {
		return errors.New("invalid URIs in DC certificate")
	}

	if cert.URIs[0].Scheme != "vnet-conf" {
		return errors.New("invalid URI scheme in DC certificate")
	}

	n.DCState.Lock()
	defer n.DCState.Unlock()

	if n.DCState.Config != nil && (cert.NotBefore.Before(n.DCState.updateTime) || cert.NotBefore.Equal(n.DCState.updateTime)) {
		return errors.New("received DC is not newer than our current one, rejected")
	}

	hashSum, err := hex.DecodeString(cert.URIs[0].Host)
	if err != nil {
		return errors.New("invalid hash sum in DC certificate")
	}

	computedHash := sha256.Sum256(dc.Content)
	if !bytes.Equal(computedHash[:], hashSum) {
		return errors.New("hash mismatch between DC certificate and content")
	}

	var dconf DistributedConfig

	err = json.Unmarshal(dc.Content, &dconf)
	if err != nil {
		return errors.New("cannot decode distributed config")
	}

	n.DCState.Config = &dconf
	n.DCState.RawConfig = dc
	n.DCState.updateTime = cert.NotBefore

	n.DCState.updatePrefixWhitelistTableLocked()

	return nil
}

func (n *Node) DispatchIPPacket(payload []byte) error {
	var ip6 layers.IPv6
	decoded := []gopacket.LayerType{}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6)
	parser.IgnoreUnsupported = true
	if err := parser.DecodeLayers(payload, &decoded); err != nil {
		if EnableDebug {
			log.Println("DecodeLayers error:", err)
		}
		return errors.New("cannot decode IP packet")
	}
	if len(decoded) == 0 || decoded[0] != layers.LayerTypeIPv6 {
		return errors.New("invalid protocol payload")
	}
	if len(ip6.SrcIP) != 16 || len(ip6.DstIP) != 16 {
		return errors.New("invalid src/dst ip")
	}

	routeInfo, nextPeer, err := n.GetRouteForAddress(ip6.DstIP)
	if err != nil {
		return err
	}

	if len(routeInfo.Route.Path) == 0 {
		// Dispatch to local Vif
		// nextPeer is nil here
		if nextPeer != nil {
			panic("inconsistent routeInfo/nextPeer")
		}
		if _, err := n.Vif.Send(payload); err != nil {
			return err
		}
	} else {
		select {
		case nextPeer.Out <- &protocol.Message{Tag: uint32(MessageTag_IP), Payload: payload}:
		default:
		}
	}

	return nil
}

func (n *Node) GetRouteForAddress(_addr net.IP) (retRouteInfo RouteInfo, retPeer *Peer, retErr error) {
	if len(_addr) != 16 {
		return RouteInfo{}, nil, errors.New("invalid address")
	}

	var addr [16]byte
	copy(addr[:], _addr)
	var found bool

	if err := n.RoutingTable.Lookup(addr, 128, func(prefix [16]byte, prefixLen uint8, _routeInfo interface{}) bool {
		routeInfo := _routeInfo.(RouteInfo)
		if !routeIsValid(routeInfo) {
			n.RoutingTable.Delete(prefix, prefixLen)
			return true
		}

		if len(routeInfo.Route.Path) == 0 {
			retRouteInfo = routeInfo
			found = true
			return false // local
		}
		if peer, ok := n.Peers.Load(routeInfo.NextPeerID); ok && peer != nil {
			retRouteInfo = routeInfo
			retPeer = peer.(*Peer)
			found = true
			return false
		}
		return true
	}); err != nil {
		retErr = err
		return
	}

	if !found {
		retErr = errors.New("route not found")
	}
	return
}

func (n *Node) Run() error {
	go func() {
		for {
			buf := make([]byte, 1500)
			count, err := n.Vif.Recv(buf)
			if err != nil {
				if EnableDebug {
					log.Println("Vif recv error:", err)
				}
				continue
			}
			payload := buf[:count]
			if err := n.DispatchIPPacket(payload); err != nil {
				if EnableDebug {
					log.Println("DispatchIPPacket error:", err)
				}
			}
		}
	}()

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{n.FullCert},
		ServerName:   n.Config.ServerName,
		ClientAuth:   tls.RequireAnyClientCert,
	})

	server := grpc.NewServer(grpc.Creds(creds))
	service := &PeerServer{
		node: n,
	}
	protocol.RegisterVnetPeerServer(server, service)

	tcpListener, err := net.Listen("tcp", n.Config.ListenAddr)
	if err != nil {
		return err
	}

	return server.Serve(tcpListener)
}

func (n *Node) ConnectToAllPeers() {
	for _, peer := range n.Config.Peers {
		go n.PersistingConnect(peer.Addr, peer.Name, nil)
	}
}

func (n *Node) PersistingConnect(remoteAddr, remoteServerName string, oldError error) {
	err := oldError
	for {
		if err != nil && strings.Contains(err.Error(), "detected multiple connections") {
			// - 1. Another thread has initiated a connection. (so it is responsible for reconnecting)
			// - 2. The remote peer has actively connected to us. (so the remote peer is responsible for reconnecting)
			// In practice we do need to reconnect here sometimes. So just sleep longer.
			time.Sleep(RetryDelay * 10)
			err = nil
			continue
		}
		log.Printf("Connecting to %s/%s\n", remoteAddr, remoteServerName)
		if err = n.Connect(remoteAddr, remoteServerName, true); err != nil {
			log.Printf("Connect failed, waiting for %+v. error = %+v\n", RetryDelay, err)
			time.Sleep(RetryDelay)
			continue
		} else {
			break
		}
	}
}

func (n *Node) Connect(remoteAddr, remoteServerName string, persist bool) error {
	creds := credentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{n.FullCert},
		ServerName:         remoteServerName,
		InsecureSkipVerify: true, // verification will be handled in ProcessMessageStream
	})
	conn, err := grpc.Dial(remoteAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	client := protocol.NewVnetPeerClient(conn)
	session, err := client.Input(context.Background())
	if err != nil {
		return err
	}

	go func() {
		err := n.ProcessMessageStream(session)

		closeErr := session.CloseSend()
		if closeErr != nil {
			log.Println("CloseSend() returns error:", closeErr)
		}

		log.Printf("Session closed, error = %+v\n", err)
		if persist {
			time.Sleep(RetryDelay)
			n.PersistingConnect(remoteAddr, remoteServerName, err)
		}
	}()
	return nil
}

type MessageStream interface {
	Send(message *protocol.Message) error
	Recv() (*protocol.Message, error)
	Context() context.Context
}

func (n *Node) ProcessMessageStream(stream MessageStream) error {
	netInfo, ok := peer2.FromContext(stream.Context())
	if !ok {
		return errors.New("cannot get network info")
	}
	tlsInfo, ok := netInfo.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return errors.New("cannot get tls info")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return errors.New("peer did not provide any certificates")
	}

	remoteCert := tlsInfo.State.PeerCertificates[0]
	remoteName := remoteCert.Subject.CommonName
	remoteID := peerIDFromCertificate(remoteCert)

	_, err := remoteCert.Verify(x509.VerifyOptions{
		Roots: n.CAPool,
	})
	var remoteBelongsToInternalCA bool
	if err != nil {
		// Possibly an external peer
		if _, ok := n.PeerCerts.Certs[remoteID]; ok {
			err = nil
			remoteBelongsToInternalCA = false
		} else {
			return errors.New("unable to verify peer certificate")
		}
	} else {
		remoteBelongsToInternalCA = true
	}

	// If we are in different domains or under different CAs
	if !strings.HasSuffix(remoteName, "."+n.Domain) || !remoteBelongsToInternalCA {
		log.Printf("Attempting to establish connection with an external peer with name: %s.", remoteName)
	}

	peerOut := make(chan *protocol.Message, 128)

	peer := &Peer{
		Node:       n,
		LocalCert:  n.FullCert.Leaf,
		LocalID:    n.LocalID,
		RemoteCert: remoteCert,
		RemoteID:   remoteID,
		RemoteName: remoteName,
		Out:        peerOut,

		atomicLatency: math.MaxUint32, // before we get the latency measurement information
	}

	if _, loaded := n.Peers.LoadOrStore(remoteID, nil); loaded {
		return errors.New("detected multiple connections from a single remote peer")
	}

	stop := make(chan struct{})
	if err := peer.Start(); err != nil {
		n.Peers.Delete(remoteID)
		return err
	}

	n.Peers.Store(remoteID, peer)

	fullyClosed := make(chan struct{})

	go func() {
		defer func() {
			peer.Stop()
			n.Peers.Delete(remoteID)
			close(fullyClosed)
		}()

		for {
			select {
			case msg := <-peerOut:
				err := stream.Send(msg)
				if err != nil {
					return
				}
			case <-stop:
				return
			}
		}
	}()

	defer func() {
		close(stop)
		<-fullyClosed
	}()

	log.Printf("Initialized stream with peer %x (%s)\n", peer.RemoteID, peer.RemoteName)

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := peer.HandleMessage(msg); err != nil {
			return err
		}
	}
}

type PeerServer struct {
	node *Node
}

func (p *PeerServer) Input(server protocol.VnetPeer_InputServer) error {
	return p.node.ProcessMessageStream(server)
}

func peerIDFromCertificate(cert *x509.Certificate) PeerID {
	return sha256.Sum256(cert.Raw)
}

func routeIsValid(info RouteInfo) bool {
	if len(info.Route.Path) == 0 {
		// local route
		return true
	}

	currentTime := time.Now()
	if currentTime.After(info.UpdateTime) && currentTime.Sub(info.UpdateTime) > RouteTimeout {
		return false
	}
	return true
}
