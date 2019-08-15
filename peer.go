package vnet

import (
	"bytes"
	"crypto/x509"
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/losfair/vnet/protocol"
	"log"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type MessageTag uint32

const (
	MessageTag_Invalid MessageTag = iota
	MessageTag_IP
	MessageTag_Announce
	MessageTag_Ping
	MessageTag_Pong
)

type PeerID [32]byte

type Peer struct {
	Node       *Node
	LocalCert  *x509.Certificate
	LocalID    PeerID
	RemoteCert *x509.Certificate
	RemoteID   PeerID
	Out        chan<- *protocol.Message

	stop chan struct{}

	latency       LatencyMeasurementState
	atomicLatency uint32
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
			}

			addRoute := true

			if _oldRoute, ok := p.Node.Routes[int(rt.PrefixLength)].Load(prefix); ok {
				oldRoute := _oldRoute.(RouteInfo)

				// Should forward to local vif
				if len(oldRoute.Route.Path) == 0 {
					addRoute = false
				} else {
					if _, ok := p.Node.Peers.Load(oldRoute.NextPeerID); ok {
						// Allow 10ms fluctuation on latency
						if oldRoute.TotalLatency <= info.TotalLatency || oldRoute.TotalLatency-info.TotalLatency < 10 {
							addRoute = false
						}
					}
				}
			}

			if addRoute {
				log.Printf("Adding route. Prefix = %+v, PrefixLength = %d, NextHop = %x\n", net.IP(prefix[:]), rt.PrefixLength, info.NextPeerID)
				p.Node.Routes[int(rt.PrefixLength)].Store(prefix, info)
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
			return errors.New("Pong received without a previous Ping")
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
	default:
		return errors.New("unknown message tag")
	}
}

func (p *Peer) Start() error {
	p.stop = make(chan struct{})

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				// Test latency.
				{
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

				routes := make([]*protocol.Route, 0)
				for i, _ := range p.Node.Routes {
					m := &p.Node.Routes[i]
					m.Range(func(_, _info interface{}) bool {
						info := _info.(RouteInfo)
						route := *info.Route
						route.Path = append([]*protocol.Hop{{
							Id:      p.LocalID[:],
							Latency: p.GetLatencyMs(),
						}}, route.Path...)
						routes = append(routes, &route)
						return true
					})
				}
				ann := &protocol.Announcement{Routes: routes}
				serialized, err := proto.Marshal(ann)
				if err != nil {
					continue
				}
				select {
				case p.Out <- &protocol.Message{Tag: uint32(MessageTag_Announce), Payload: serialized}:
				default:
				}
			}
		}
	}()
	return nil
}

func (p *Peer) Stop() {
	close(p.stop)
}
