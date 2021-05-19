package vmesh

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/losfair/vmesh/protocol"
	"google.golang.org/protobuf/proto"
)

type MessageTag uint32

const (
	MessageTag_Invalid MessageTag = iota
	MessageTag_IP
	MessageTag_Announce
	MessageTag_Ping
	MessageTag_Pong
	MessageTag_UpdateDistributedConfig

	MessageTag_ChannelRequest
	MessageTag_ChannelResponse
)

type PeerID [32]byte

type Peer struct {
	Node       *Node
	LocalCert  *x509.Certificate
	LocalID    PeerID
	RemoteCert *x509.Certificate
	RemoteID   PeerID
	RemoteName string
	Out        chan<- *protocol.Message

	stop chan struct{}

	latency       LatencyMeasurementState
	atomicLatency uint32

	channelKey [32]byte

	udp UDPChannel
}

type UDPChannel struct {
	mu             sync.Mutex
	peerToken      [32]byte
	peerAddr       *net.UDPAddr
	peerUpdateTime time.Time
}

type LatencyMeasurementState struct {
	sync.Mutex
	inProgress   bool
	measureStart time.Time
}

func (p *Peer) GetLatencyMs() uint32 {
	return atomic.LoadUint32(&p.atomicLatency)
}

func (p *Peer) HandleMessage(msg *protocol.Message) error {
	tag := MessageTag(msg.Tag)

	switch tag {
	case MessageTag_IP:
		if err := p.Node.DispatchIPPacket(msg.Payload); err != nil {
			if EnableDebug {
				log.Println("DispatchIPPacket error:", err)
			}
		}
		return nil
	case MessageTag_Announce:
		var payload protocol.Announcement
		if err := proto.Unmarshal(msg.Payload, &payload); err != nil {
			return errors.New("cannot unmarshal payload for Announce")
		}
		if len(payload.Routes) > 65536 {
			return errors.New("too many routes from a single peer")
		}

		for _, rt := range payload.Routes {
			var totalLatency uint64

			if len(rt.Prefix) != 16 || rt.PrefixLength > 128 {
				return errors.New("invalid prefix")
			}

			var prefix [16]byte
			copy(prefix[:], rt.Prefix)

			if !p.Node.DCState.PrefixIsWhitelisted(p.RemoteName, prefix, uint8(rt.PrefixLength)) {
				// Explicitly not whitelisted
				continue
			}

			if len(rt.Path) == 0 || !bytes.Equal(rt.Path[0].Id, p.RemoteID[:]) {
				return errors.New("invalid path")
			}

			var circularRoute bool

			for _, hop := range rt.Path {
				if bytes.Equal(hop.Id, p.LocalID[:]) {
					circularRoute = true
					break
				}
				totalLatency += uint64(hop.Latency)
			}

			if circularRoute {
				continue
			}

			info := RouteInfo{
				Route:        rt,
				NextPeerID:   p.RemoteID,
				TotalLatency: totalLatency,
				UpdateTime:   time.Now(),
			}

			addRoute := true
			displayRouteUpdateMessage := true

			if err := p.Node.RoutingTable.Lookup(prefix, uint8(rt.PrefixLength), func(gotPrefix [16]byte, gotPrefixLen uint8, _oldRoute interface{}) bool {
				if uint32(gotPrefixLen) != rt.PrefixLength {
					return false
				}

				oldRoute := _oldRoute.(RouteInfo)

				// Rules:
				// - If this route points to the local vif, do not add route.
				// - If the old route is too old, add route.
				// - (majority case) If the old peer is alive, the updated route comes from the same peer, and that peer does not have major change in its route, add route without displaying message.
				// - If the old peer is alive, the updated route comes from the same peer, and that peer has major change in its route, add route.
				// - If the old peer is alive, the updated route comes from a different peer and does not have a latency of at least 10ms lower than our current one, do not add route.
				// - Otherwise, add route.
				if len(oldRoute.Route.Path) == 0 {
					addRoute = false
				} else if info.UpdateTime.After(oldRoute.UpdateTime) && info.UpdateTime.Sub(oldRoute.UpdateTime) > RouteTimeout {
					// add route
				} else {
					if _, ok := p.Node.Peers.Load(oldRoute.NextPeerID); ok {
						if oldRoute.NextPeerID == info.NextPeerID {
							// Most time this branch should be hit.
							if hopPathSimilar(oldRoute.Route, info.Route) {
								displayRouteUpdateMessage = false
							}
						} else {
							if oldRoute.TotalLatency <= info.TotalLatency || oldRoute.TotalLatency-info.TotalLatency < 10 {
								addRoute = false
							}
						}
					}
				}
				return false
			}); err != nil {
				return err
			}

			if addRoute {
				if displayRouteUpdateMessage {
					log.Printf("Updating route. Prefix = %+v, PrefixLength = %d, NextHop = %x, Latency = %d\n", net.IP(prefix[:]), rt.PrefixLength, info.NextPeerID, info.TotalLatency)
				}
				if err := p.Node.RoutingTable.Insert(prefix, uint8(rt.PrefixLength), info); err != nil {
					log.Println("Unable to insert route into routing table:", err)
				}
			}
		}

		return nil
	case MessageTag_Ping:
		select {
		case p.Out <- &protocol.Message{Tag: uint32(MessageTag_Pong)}:
		default:
		}
		return nil
	case MessageTag_Pong:
		p.latency.Lock()
		defer p.latency.Unlock()

		if !p.latency.inProgress {
			return errors.New("pong received without a previous Ping")
		}
		p.latency.inProgress = false
		now := time.Now()
		if now.Before(p.latency.measureStart) {
			log.Println("Ignoring Pong as now.Before(p.latency.measureStart) == true")
			return nil
		}
		latencyMs := uint32(now.Sub(p.latency.measureStart).Nanoseconds() / int64(time.Millisecond))
		oldLatencyMs := atomic.LoadUint32(&p.atomicLatency)

		// latency is known before...
		if oldLatencyMs != math.MaxUint32 {
			latencyMs = uint32((uint64(oldLatencyMs) + uint64(latencyMs)) / 2)
		}

		atomic.StoreUint32(&p.atomicLatency, latencyMs)
		return nil
	case MessageTag_UpdateDistributedConfig:
		var dconf protocol.DistributedConfig
		if err := proto.Unmarshal(msg.Payload, &dconf); err != nil {
			if EnableDebug {
				log.Println("Unable to unmarshal received distributed config")
			}
			return nil
		}

		if err := p.Node.UpdateDistributedConfig(&dconf); err != nil {
			if EnableDebug {
				log.Println("Error updating distributed config:", err)
			}
			return nil
		} else {
			log.Println("Applied distributed config.")
		}
		return nil
	case MessageTag_ChannelRequest:
		var req protocol.ChannelRequest
		if err := proto.Unmarshal(msg.Payload, &req); err == nil {
			if req.Type == protocol.ChannelType_UDP {
				p.udp.mu.Lock()
				copy(p.udp.peerToken[:], req.Token)
				p.udp.peerUpdateTime = time.Now()
				p.udp.mu.Unlock()

				payload := &protocol.ChannelResponse{
					Type:  protocol.ChannelType_UDP,
					Token: p.channelKey[:],
				}
				marshaled, err := proto.Marshal(payload)
				if err == nil {
					select {
					case p.Out <- &protocol.Message{Tag: uint32(MessageTag_ChannelResponse), Payload: marshaled}:
					default:
					}
				}
			}
		}
		return nil
	case MessageTag_ChannelResponse:
		var resp protocol.ChannelResponse
		if err := proto.Unmarshal(msg.Payload, &resp); err == nil {
			if resp.Type == protocol.ChannelType_UDP {
				p.udp.mu.Lock()
				copy(p.udp.peerToken[:], resp.Token)
				p.udp.peerUpdateTime = time.Now()
				p.udp.mu.Unlock()
			}
		}
		return nil
	default:
		return nil
	}
}

func (p *Peer) Start() error {
	p.stop = make(chan struct{})

	if _, err := rand.Read(p.channelKey[:]); err != nil {
		return err
	}

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		secs := uint64(0)

		for ; ; secs++ {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				// UDP keepalive.
				if secs%1 == 0 {
					p.udp.mu.Lock()
					if p.udp.peerAddr != nil && p.udp.peerToken != [32]byte{} {
						if encoded, ok := p.encodeLocked(nil); ok {
							_, _ = p.Node.UDPChannelListener.WriteTo(encoded, p.udp.peerAddr)
						}
					}
					p.udp.mu.Unlock()
				}

				// Test latency.
				if (secs+1)%10 == 0 {
					p.latency.Lock()
					if !p.latency.inProgress {
						select {
						case p.Out <- &protocol.Message{Tag: uint32(MessageTag_Ping)}:
							p.latency.inProgress = true
							p.latency.measureStart = time.Now()
						default:
						}
					}
					p.latency.Unlock()
				}

				// Send distributed config.
				if (secs+2)%30 == 0 {
					p.Node.DCState.Lock()
					dconf := p.Node.DCState.RawConfig
					p.Node.DCState.Unlock()

					if dconf != nil {
						serialized, err := proto.Marshal(dconf)
						if err != nil {
							log.Println("Unable to marshal distributed config:", err)
						} else {
							select {
							case p.Out <- &protocol.Message{Tag: uint32(MessageTag_UpdateDistributedConfig), Payload: serialized}:
							default:
							}
						}
					}
				}

				// Announce routes.
				if (secs+3)%30 == 0 {
					routes := make([]*protocol.Route, 0)
					p.Node.RoutingTable.Range(func(prefix [16]byte, prefixLen uint8, _info interface{}) bool {
						info := _info.(RouteInfo)
						if !routeIsValid(info) {
							p.Node.RoutingTable.Delete(prefix, prefixLen)
							return true
						}

						route := info.Route
						route.Path = append([]*protocol.Hop{{
							Id:      p.LocalID[:],
							Latency: p.GetLatencyMs(),
						}}, route.Path...)
						routes = append(routes, route)
						return true
					})
					ann := &protocol.Announcement{Routes: routes}
					serialized, err := proto.Marshal(ann)
					if err != nil {
						log.Println("Unable to marshal announcement:", err)
					} else {
						select {
						case p.Out <- &protocol.Message{Tag: uint32(MessageTag_Announce), Payload: serialized}:
						default:
						}
					}
				}
			}
		}
	}()
	return nil
}

func (p *Peer) Stop() {
	close(p.stop)
}

func (p *Peer) encodeLocked(payload []byte) ([]byte, bool) {
	outLen := 32 + 32 + len(payload)
	if outLen > 1500 {
		return nil, false
	}
	ret := make([]byte, outLen)
	copy(ret[0:32], p.LocalID[:])
	copy(ret[32:64], p.udp.peerToken[:])
	copy(ret[64:], payload)
	return ret, true
}

func (p *Peer) udpCanSendLocked() bool {
	t := time.Now()
	return p.udp.peerAddr != nil && t.After(p.udp.peerUpdateTime) && t.Sub(p.udp.peerUpdateTime) < 5*time.Second
}

func (p *Peer) HandleUDPRecv(raddr *net.UDPAddr, payload []byte) {
	if len(payload) < 64 || !bytes.Equal(payload[0:32], p.RemoteID[:]) || !bytes.Equal(payload[32:64], p.channelKey[:]) {
		return
	}

	p.udp.mu.Lock()
	p.udp.peerUpdateTime = time.Now()
	if p.udp.peerAddr == nil || !p.udp.peerAddr.IP.Equal(raddr.IP) || p.udp.peerAddr.Port != raddr.Port {
		log.Printf("Received new UDP address for peer %x: %+v\n", p.RemoteID, raddr)
	}
	p.udp.peerAddr = raddr
	p.udp.mu.Unlock()

	body := payload[64:]
	if len(body) > 0 {
		if err := p.HandleMessage(&protocol.Message{
			Tag:     uint32(MessageTag_IP),
			Payload: body,
		}); err != nil {
			if EnableDebug {
				log.Println(err)
			}
		}
	}
}

func (p *Peer) SendUDP(payload []byte) bool {
	p.udp.mu.Lock()

	if p.udpCanSendLocked() {
		if encoded, ok := p.encodeLocked(payload); ok {
			peerAddr := p.udp.peerAddr
			p.udp.mu.Unlock()

			if _, err := p.Node.UDPChannelListener.WriteTo(encoded, peerAddr); err == nil {
				return true
			} else {
				return false
			}
		}
	}

	p.udp.mu.Unlock()
	return false
}

func hopPathSimilar(left, right *protocol.Route) bool {
	if len(left.Path) != len(right.Path) {
		return false
	}

	var leftTotalLatency uint64
	var rightTotalLatency uint64

	for i, leftHop := range left.Path {
		rightHop := right.Path[i]
		if !bytes.Equal(leftHop.Id, rightHop.Id) {
			return false
		}

		leftLatency, rightLatency := uint64(leftHop.Latency), uint64(rightHop.Latency)
		if AbsDiffUint64(leftLatency, rightLatency) > 5 {
			return false
		}

		leftTotalLatency += leftLatency
		rightTotalLatency += rightLatency
	}

	return AbsDiffUint64(leftTotalLatency, rightTotalLatency) < 10
}

func AbsDiffUint64(left, right uint64) uint64 {
	if left > right {
		return left - right
	} else {
		return right - left
	}
}
