package vmesh

import (
	"errors"
	"log"
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
	conn                   net.Conn
	lastReconnect          time.Time
	reconnectionInProgress uint32 // atomic
}

func NewBackingService(name string, network, address string) (*BackingService, error) {
	switch network {
	case "unixgram":
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
		if _, err := s.conn.Write(data); err != nil {
			log.Println("Failed to send packet to backing service:", err)
		} else {
			return len(data), nil
		}
	} else {
		log.Println("No connection. Triggering reconnect.")
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
	case "unixgram":
		if addr, err := net.ResolveUnixAddr(s.network, s.address); err != nil {
			//log.Println("Failed to resolve unix address:", err)
		} else {
			if conn, err := net.DialUnix(s.network, nil, addr); err != nil {
				//log.Println("Failed to dial unix socket:", err)
			} else {
				s.mu.Lock()
				s.conn = conn
				s.mu.Unlock()
				log.Println("Connection to unixgram socket", s.address, "established")
			}
		}
	default:
		return
	}
}

func (s *BackingService) Recv(data []byte) (int, error) {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()

	if conn != nil {
		if n, err := conn.Read(data); err == nil {
			return n, nil
		}
	}

	s.mu.Lock()
	s.triggerReconnect()
	s.mu.Unlock()

	return 0, errors.New("Dead connection to the backing service. Trying to reconnect.")
}
