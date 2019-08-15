package vnet

import (
	"bytes"
	"crypto/x509"
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/losfair/vnet/protocol"
	"log"
	"net"
	"time"
)

type MessageTag uint32

const (
	MessageTag_Invalid MessageTag = iota
	MessageTag_IP
	MessageTag_Announce
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
						if oldRoute.TotalLatency <= info.TotalLatency {
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
				routes := make([]*protocol.Route, 0)
				for i, _ := range p.Node.Routes {
					m := &p.Node.Routes[i]
					m.Range(func(_, _info interface{}) bool {
						info := _info.(RouteInfo)
						route := *info.Route
						route.Path = append([]*protocol.Hop{{
							Id:      p.LocalID[:],
							Latency: 1,
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
