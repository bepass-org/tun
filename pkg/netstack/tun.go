package netstack

import "github.com/bepass-org/tun/internal/tun"

type TunInterface struct {
	LinkEP *WintunEndpoint
	device tun.Device
}

func NewTunDevice(tunName string) (*TunInterface, error) {
	tunIface := TunInterface{}
	wgtun, err := tun.CreateTUN(tunName, 1500)
	if err != nil {
		return nil, err
	}
	tunIface.LinkEP = NewWintunEndpoint(wgtun, 1500)
	tunIface.device = wgtun
	return &tunIface, nil
}

func (i *TunInterface) Name() (string, error) {
	return i.device.Name()
}

func (i *TunInterface) Close() error {
	return i.device.Close()
}
