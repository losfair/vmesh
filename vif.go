package vnet

type Vif interface {
	GetName() string
	Send([]byte) (int, error)
	Recv([]byte) (int, error)
}

type DummyVif struct{}

func (*DummyVif) GetName() string {
	return "(dummy)"
}

func (*DummyVif) Send(data []byte) (int, error) {
	return len(data), nil
}

func (*DummyVif) Recv(data []byte) (int, error) {
	select {}
}
