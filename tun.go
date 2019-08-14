package vnet

import (
	"github.com/songgao/water"
)

type Vif interface {
	GetName() string
	Send([]byte) (int, error)
	Recv([]byte) (int, error)
}

type Tun struct {
	ifce *water.Interface
}

func NewTun() (*Tun, error) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
		//PlatformSpecificParams: water.PlatformSpecificParams{ Name: os.Args[3], Persist: true },
	})
	if err != nil {
		return nil, err
	}

	return &Tun{
		ifce: ifce,
	}, nil
}

func (t *Tun) GetName() string {
	return t.ifce.Name()
}

func (t *Tun) Send(data []byte) (int, error) {
	return t.ifce.Write(data)
}

func (t *Tun) Recv(data []byte) (int, error) {
	return t.ifce.Read(data)
}
