package vmesh

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
	"github.com/golang/protobuf/proto"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/losfair/vmesh/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	peer2 "google.golang.org/grpc/peer"
	"io/ioutil"
	"log"
	"math"
	"net"
	"sort"
	"strconv"
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

	Vifs map[string]Vif

	DCState DistributedConfigState

	UDPChannelAddr     *net.UDPAddr
	UDPChannelListener net.PacketConn
}

type PeerCertCollection struct {
	Certs map[PeerID]*x509.Certificate
}

type RouteInfo struct {
	Route        *protocol.Route
	NextPeerID   PeerID
	TotalLatency uint64
	UpdateTime   time.Time
	Vif          Vif // only for local routes
}

type NodeConfig struct {
	ListenAddr            string               `json:"listen_addr"`
	CAPath                string               `json:"ca"`
	ExternalPeerCertPaths []string             `json:"external_peer_certs"`
	CertPath              string               `json:"cert"`
	PrivateKeyPath        string               `json:"private_key"`
	ServerName            string               `json:"server_name"`
	LocalAnnouncements    []LocalAnnouncement  `json:"local_announcements"`
	Peers                 []PeerConfig         `json:"peers"`
	Vifs                  map[string]VifConfig `json:"vifs"`
}

type LocalAnnouncement struct {
	Prefix string `json:"prefix"`
	Vif    string `json:"vif"`
}

type VifConfig struct {
	Type string `json:"type"` // required

	// for type: tun
	TunName string `json:"tun_name"`

	// for type: api
	APIKey string `json:"api_key"`
}

type PrefixWhitelistEntryProps struct {
	MaxPrefixLen uint8
}

func ParsePrefixWhitelistEntry(entry string) (string, PrefixWhitelistEntryProps) {
	parts := strings.Split(entry, ",")
	props := PrefixWhitelistEntryProps{
		MaxPrefixLen: 128,
	}

	for i := 1; i < len(parts); i++ {
		parts := strings.SplitN(parts[i], "=", 2)
		key := parts[0]
		value := "true"
		if len(parts) == 2 {
			value = parts[1]
		}

		switch key {
		case "max_prefix_len":
			if mpl, err := strconv.ParseUint(value, 10, 8); err == nil {
				if mpl <= 128 {
					props.MaxPrefixLen = uint8(mpl)
				}
			}
		default:
		}
	}
	return parts[0], props
}

type DistributedConfigState struct {
	sync.Mutex
	updateTime time.Time
	Config     *DistributedConfig
	RawConfig  *protocol.DistributedConfig

	PrefixWhitelistTable map[string]*LikeRoutingTable // typeof value = PrefixWhitelistEntryProps
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

	_ = table.Lookup(prefix, prefixLen, func(_ [16]byte, _ uint8, _props interface{}) bool {
		props := _props.(PrefixWhitelistEntryProps)
		if prefixLen <= props.MaxPrefixLen {
			found = true
			return false
		} else {
			return true
		}
	})

	return found
}

func (s *DistributedConfigState) updatePrefixWhitelistTableLocked() {
	s.PrefixWhitelistTable = make(map[string]*LikeRoutingTable)

	for name, allowed := range s.Config.PrefixWhitelist {
		table := &LikeRoutingTable{}
		for _, elem := range allowed {
			cidr, props := ParsePrefixWhitelistEntry(elem)
			if err := table.InsertCIDR(cidr, props); err != nil {
				log.Println("failed to insert CIDR-format network into whitelist:", err)
			}
			log.Printf("Added prefix whitelist entry. Prefix = %s, MaxPrefixLen = %d\n", cidr, props.MaxPrefixLen)
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
	UDP  bool   `json:"udp"`
}

func (c *VifConfig) Init() (Vif, error) {
	switch c.Type {
	case "tun":
		return NewTun(c.TunName)
	case "dummy":
		return (*DummyVif)(nil), nil
	default:
		return nil, errors.New("invalid vif type")
	}
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

	vifs := make(map[string]Vif)

	for key, c := range config.Vifs {
		vif, err := c.Init()
		if err != nil {
			return nil, fmt.Errorf("Failed to init vif '%s': %+v", key, err)
		}
		vifs[key] = vif
		log.Printf("Initialized virtual interface '%s'\n", key)
	}

	domainParts := strings.SplitN(fullCert.Leaf.Subject.CommonName, ".", 2)
	if len(domainParts) != 2 {
		return nil, errors.New("invalid common name")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", config.ListenAddr)
	if err != nil {
		return nil, err
	}

	n := &Node{
		Config:    config,
		CAPool:    caPool,
		CA:        ca,
		PeerCerts: peerCerts,
		FullCert:  fullCert,
		LocalID:   peerIDFromCertificate(fullCert.Leaf),
		Domain:    domainParts[1],
		Vifs:      vifs,
		DCState: DistributedConfigState{
			PrefixWhitelistTable: make(map[string]*LikeRoutingTable),
		},
		UDPChannelAddr: udpAddr,
	}

	log.Printf("Local ID: %x\n", n.LocalID)
	log.Println("Domain:", n.Domain)
	log.Println("Local name:", n.FullCert.Leaf.Subject.CommonName)

	if len(config.LocalAnnouncements) > 0 {
		for _, ann := range config.LocalAnnouncements {
			_, ipnet, err := net.ParseCIDR(ann.Prefix)
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
				Vif:          n.Vifs[ann.Vif], // nil by default
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
		if routeInfo.Vif != nil {
			if _, err := routeInfo.Vif.Send(payload); err != nil {
				return err
			}
		} else {
			return errors.New("vif unavailable")
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

func (n *Node) processVifPackets(vif Vif) {
	for {
		buf := make([]byte, 1500)
		count, err := vif.Recv(buf)
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
}

func (n *Node) processUDPPackets() {
	buf := make([]byte, 1500)

	for {
		readN, raddr, err := n.UDPChannelListener.ReadFrom(buf)
		if err != nil || readN == 0 {
			continue
		}

		buf := buf[:readN]
		if len(buf) < 64 {
			continue
		}

		var peerID PeerID
		copy(peerID[:], buf[:32])

		_peer, ok := n.Peers.Load(peerID)
		if !ok {
			continue
		}

		peer := _peer.(*Peer)
		copied := append([]byte{}, buf...)
		peer.HandleUDPRecv(raddr.(*net.UDPAddr), copied)
	}
}

func (n *Node) Run() error {
	for _, vif := range n.Vifs {
		go n.processVifPackets(vif)
	}

	// Insecure channel
	udpListener, err := net.ListenUDP("udp", n.UDPChannelAddr)
	if err != nil {
		return err
	}

	n.UDPChannelListener = udpListener
	go n.processUDPPackets()

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{n.FullCert},
		ServerName:   n.Config.ServerName,
		ClientAuth:   tls.RequireAnyClientCert,
	})

	server := grpc.NewServer(grpc.Creds(creds), grpc.KeepaliveParams(keepalive.ServerParameters{
		Time:    30 * time.Second,
		Timeout: 10 * time.Second,
	}))
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
		go n.PersistingConnect(peer, nil)
	}
}

func (n *Node) PersistingConnect(peer PeerConfig, oldError error) {
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
		log.Printf("Connecting to %s/%s\n", peer.Addr, peer.Name)
		if err = n.Connect(peer, true); err != nil {
			log.Printf("Connect failed, waiting for %+v. error = %+v\n", RetryDelay, err)
			time.Sleep(RetryDelay)
			continue
		} else {
			break
		}
	}
}

func (n *Node) Connect(peer PeerConfig, persist bool) error {
	creds := credentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{n.FullCert},
		ServerName:         peer.Name,
		InsecureSkipVerify: true, // verification will be handled in ProcessMessageStream
	})
	conn, err := grpc.Dial(peer.Addr, grpc.WithTransportCredentials(creds), grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:    30 * time.Second,
		Timeout: 10 * time.Second,
	}))
	if err != nil {
		return err
	}
	client := protocol.NewVnetPeerClient(conn)
	session, err := client.Input(context.Background())
	if err != nil {
		return err
	}

	go func() {
		err := n.ProcessMessageStream(session, &peer)

		closeErr := session.CloseSend()
		if closeErr != nil {
			log.Println("CloseSend() returns error:", closeErr)
		}

		log.Printf("Session closed, error = %+v\n", err)
		if persist {
			time.Sleep(RetryDelay)
			n.PersistingConnect(peer, err)
		}
	}()
	return nil
}

type MessageStream interface {
	Send(message *protocol.Message) error
	Recv() (*protocol.Message, error)
	Context() context.Context
}

func (n *Node) ProcessMessageStream(stream MessageStream, peerConfig *PeerConfig) error {
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

	if peerConfig != nil {
		if peerConfig.UDP {
			if udpAddr, err := net.ResolveUDPAddr("udp", peerConfig.Addr); err == nil {
				peer.udp.mu.Lock()
				peer.udp.peerAddr = udpAddr
				peer.udp.mu.Unlock()

				marshaled, err := proto.Marshal(&protocol.ChannelRequest{
					Type:  protocol.ChannelType_UDP,
					Token: peer.channelKey[:], // initialized in peer.Start()
				})
				if err == nil {
					select {
					case peer.Out <- &protocol.Message{Tag: uint32(MessageTag_ChannelRequest), Payload: marshaled}:
					default:
						log.Println("Warning: Failed to send channel request")
					}
				}
			} else {
				log.Println("Warning: Cannot decode peer address for UDP")
			}
		}
	}

	fullyClosed := make(chan struct{})

	go func() {
		defer func() {
			peer.Stop()
			n.Peers.Delete(remoteID)
			close(fullyClosed)
		}()

	outer:
		for {
			select {
			case msg := <-peerOut:
				if MessageTag(msg.Tag) == MessageTag_IP && peer.SendUDP(msg.Payload) {
					goto outer
				}

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
	return p.node.ProcessMessageStream(server, nil)
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
