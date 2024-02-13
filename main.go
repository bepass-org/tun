package main

import (
	"context"
	"fmt"
	"github.com/bepass-org/tun/pkg/netstack"
	"github.com/sirupsen/logrus"
)

const (
	MaxConnectionHandler = 4096
)

type BepassTunnel struct {
	nstack *netstack.NetStack
}

func NewBepassTunnel(stackSettings netstack.StackSettings) (*BepassTunnel, error) {
	// Create a new stack, but without connPool.
	// The connPool will be created when using the *start* command
	nstack, err := netstack.NewStack(stackSettings, nil)
	if err != nil {
		return nil, err
	}
	return &BepassTunnel{nstack: nstack}, nil
}

func (t *BepassTunnel) HandleSession(ctx context.Context) {

	// Create a new, empty, connpool to store connections/packets
	connPool := netstack.NewConnPool(MaxConnectionHandler)
	t.nstack.SetConnPool(&connPool)

	// Cleanup pool if channel is closed
	defer connPool.Close()

	for {
		select {
		case <-ctx.Done():
			t.Close()
			return
		case <-connPool.CloseChan: // pool closed, we can't process packets!
			logrus.Infof("Connection pool closed")
			t.Close()
			return
		case tunnelPacket := <-connPool.Pool: // Process connections/packets
			fmt.Println(tunnelPacket)
		}
	}
}

func (t *BepassTunnel) GetStack() *netstack.NetStack {
	return t.nstack
}

func (t *BepassTunnel) Close() {
	t.nstack.Close()
}

func main() {
	BepassStack, err := NewBepassTunnel(netstack.StackSettings{
		TunName:     "uoosef",
		MaxInflight: 4096,
	})
	if err != nil {
		logrus.Error("Unable to create tunnel, err:", err)
		return
	}
	defer BepassStack.Close()
	ctx, cancelTunnel := context.WithCancel(context.Background())
	defer cancelTunnel()
	BepassStack.HandleSession(ctx)
}
