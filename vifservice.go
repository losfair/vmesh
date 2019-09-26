package vmesh

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type BackingService struct {
	name    string
	network string
	address string

	mu                     sync.Mutex
	conn                   net.PacketConn
	lastReconnect          time.Time
	reconnectionInProgress uint32 // atomic
}

func NewBackingService(name string, network, address string) (*BackingService, error) {
	switch network {
	case "unixpacket":
	default:
		return nil, errors.New("Unsupported network type")
	}

	return &BackingService{
		name:    name,
		network: network,
		address: address,
	}, nil
}

func (s *BackingService) GetName() string {
	return s.name
}

func (s *BackingService) Send(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		if n, err := s.conn.WriteTo(data, nil); err == nil {
			return n, nil
		}
	}

	s.triggerReconnect()
	return 0, errors.New("Dead connection to the backing service. Trying to reconnect.")
}

func (s *BackingService) triggerReconnect() {
	current := time.Now()
	if current.Before(s.lastReconnect) || current.Sub(s.lastReconnect) > 1*time.Second {
		s.lastReconnect = current
		go s.doReconnect()
	}
}

func (s *BackingService) doReconnect() {
	// Ensure that at most one doReconnect() is running.
	if !atomic.CompareAndSwapUint32(&s.reconnectionInProgress, 0, 1) {
		return
	}
	defer atomic.StoreUint32(&s.reconnectionInProgress, 0)

	switch s.network {
	case "unixpacket":
		if addr, err := net.ResolveUnixAddr(s.network, s.address); err == nil {
			if conn, err := net.DialUnix(s.network, nil, addr); err == nil {
				s.mu.Lock()
				s.conn = conn
				s.mu.Unlock()
			}
		}
	default:
		return
	}
}

func (s *BackingService) Recv(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		if n, _, err := s.conn.ReadFrom(data); err == nil {
			return n, nil
		}
	}

	s.triggerReconnect()
	return 0, errors.New("Dead connection to the backing service. Trying to reconnect.")
}
