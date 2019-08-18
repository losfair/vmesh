package vnet

import (
	"errors"
	"net"
	"sync"
)

type LikeRoutingTable struct {
	Routes [129]sync.Map // prefix_len -> (IPV6 Address ([16]byte) -> interface{})
}

func (r *LikeRoutingTable) Range(callback func([16]byte, uint8, interface{}) bool) {
	for i := 128; i >= 0; i-- {
		cont := true
		r.Routes[i].Range(func(addr, value interface{}) bool {
			cont = callback(addr.([16]byte), uint8(i), value)
			return cont
		})
		if !cont {
			return
		}
	}
}

func (r *LikeRoutingTable) Lookup(prefix [16]byte, prefixLen uint8, callback func(prefix [16]byte, prefixLen uint8, value interface{}) bool) error {
	if prefixLen > 128 {
		return errors.New("invalid prefix length")
	}

	for i := int(prefixLen); i >= 0; i-- {
		if i != 128 {
			prefix[i/8] &= 0xff << uint32(8-i%8)
		}
		if rt, ok := r.Routes[i].Load(prefix); ok {
			if !callback(prefix, uint8(i), rt) {
				return nil
			}
		}
	}

	return nil
}

func (r *LikeRoutingTable) Insert(prefix [16]byte, prefixLen uint8, value interface{}) error {
	if prefixLen > 128 {
		return errors.New("invalid prefix length")
	}

	for i := 127; i >= int(prefixLen); i-- {
		prefix[i/8] &= 0xff << uint32(8-i%8)
	}

	r.Routes[int(prefixLen)].Store(prefix, value)
	return nil
}

func (r *LikeRoutingTable) InsertCIDR(repr string, value interface{}) error {
	_, ipnet, err := net.ParseCIDR(repr)
	if err != nil {
		return err
	}

	if len(ipnet.IP) != 16 {
		return errors.New("only ipv6 networks are supported")
	}

	prefixLen, _ := ipnet.Mask.Size()
	var prefix [16]byte
	copy(prefix[:], ipnet.IP)
	return r.Insert(prefix, uint8(prefixLen), value)
}
