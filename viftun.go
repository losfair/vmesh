package vmesh

import (
	"github.com/songgao/water"
	"log"
)

type Tun struct {
	ifce *water.Interface
}

func NewTun(name string) (*Tun, error) {
	ifce, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: name},
	})
	if err != nil {
		return nil, err
	}

	log.Println("Created TUN interface:", ifce.Name())

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
