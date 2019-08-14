package vnet

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const RetryDelay = 10 * time.Second

type Node struct {
	Config   *NodeConfig
	CAPool   *x509.CertPool
	FullCert tls.Certificate

	// Values of the `Peers` map can be temporarily nil to indicate a peer is being initialized.
	Peers sync.Map // PeerID -> *Peer

	Routes [129]sync.Map // prefix_len -> (IPV6 Address ([16]byte) -> RouteInfo)

	Vif Vif
}

type RouteInfo struct {
	Route        *protocol.Route
	NextPeerID   PeerID
	TotalLatency uint64
}

type NodeConfig struct {
	ListenAddr         string       `json:"listen_addr"`
	CAPath             string       `json:"ca"`
	CertPath           string       `json:"cert"`
	PrivateKeyPath     string       `json:"private_key"`
	ServerName         string       `json:"server_name"`
	LocalAnnouncements []string     `json:"local_announcements"`
	Peers              []PeerConfig `json:"peers"`
	VifType            string       `json:"vif_type"`
	VifName            string       `json:"vif_name"`
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

	caRaw, err := ioutil.ReadFile(config.CAPath)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caRaw); !ok {
		return nil, errors.New("cannot load CA cert")
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

	log.Println("Virtual interface:", vif.GetName())

	n := &Node{
		Config:   config,
		CAPool:   caPool,
		FullCert: fullCert,
		Vif:      vif,
	}

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
			n.Routes[prefixLen].Store(prefix, RouteInfo{
				Route: &protocol.Route{
					Prefix:       ipnet.IP,
					PrefixLength: uint32(prefixLen),
				},
				TotalLatency: 0,
			})
		}
	}

	return n, nil
}

func (n *Node) BuildPrintableRoutingTable() string {
	builder := strings.Builder{}
	for i := 128; i >= 0; i-- {
		entry := &n.Routes[i]
		routes := make([]string, 0)
		entry.Range(func(_, _info interface{}) bool {
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
		builder.WriteString(strings.Join(routes, "\n"))
	}
	return builder.String()
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

func (n *Node) GetRouteForAddress(_addr net.IP) (RouteInfo, *Peer, error) {
	if len(_addr) != 16 {
		return RouteInfo{}, nil, errors.New("invalid address")
	}

	var addr [16]byte
	copy(addr[:], _addr)

	for i := 128; i >= 0; i-- {
		if i != 128 {
			addr[i/8] &= 0xff << uint32(8-i%8)
		}
		if rt, ok := n.Routes[i].Load(addr); ok {
			routeInfo := rt.(RouteInfo)
			if len(routeInfo.Route.Path) == 0 {
				return routeInfo, nil, nil // local
			}
			if peer, ok := n.Peers.Load(routeInfo.NextPeerID); ok && peer != nil {
				return routeInfo, peer.(*Peer), nil
			}
		}
	}

	return RouteInfo{}, nil, errors.New("route not found")
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
		ClientCAs:    n.CAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
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
			log.Println("Not reconnecting since we should already have a connection to the remote peer")
			break
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
		Certificates: []tls.Certificate{n.FullCert},
		ServerName:   remoteServerName,
		RootCAs:      n.CAPool,
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

	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return errors.New("no verified certificates")
	}

	remoteCert := tlsInfo.State.VerifiedChains[0][0]
	remoteID := peerIDFromCertificate(remoteCert)

	peerOut := make(chan *protocol.Message, 128)

	peer := &Peer{
		Node:       n,
		LocalCert:  n.FullCert.Leaf,
		LocalID:    peerIDFromCertificate(n.FullCert.Leaf),
		RemoteCert: remoteCert,
		RemoteID:   remoteID,
		Out:        peerOut,
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

	go func() {
		defer func() {
			peer.Stop()
			n.Peers.Delete(remoteID)
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

	defer close(stop)

	log.Printf("Initialized stream with peer %x\n", peer.RemoteID)

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
