// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package wlan provides an i3bar module for wireless information.
// NOTE: This module REQUIRES the external command "iwgetid",
// because getting the SSID is a privileged operation.
package wlan

import (
	"net"

	"barista.run/bar"
	"barista.run/base/value"
	"barista.run/base/watchers/netlink"
	l "barista.run/logging"
	"barista.run/outputs"
	"github.com/martinlindhe/unit"
	"github.com/mdlayher/wifi"
)

// Info represents the wireless card status.
type Info struct {
	Name           string
	State          netlink.OperState
	IPs            []net.IP
	SSID           string
	AccessPointMAC string
	// Channel        int
	Frequency       unit.Frequency
	TransmitBitrate unit.Datarate
	ReceiveBitrate  unit.Datarate
	Err             error
}

// Connecting returns true if a connection is in progress.
func (i Info) Connecting() bool {
	return i.State == netlink.Dormant
}

// Connected returns true if connected to a wireless network.
func (i Info) Connected() bool {
	return i.State == netlink.Up
}

// Enabled returns true if the wireless card is enabled.
func (i Info) Enabled() bool {
	return i.State > netlink.NotPresent
}

// Module represents a wlan bar module.
type Module struct {
	intf       string
	outputFunc value.Value // of func(Info) bar.Output
}

// Named constructs an instance of the wlan module for the specified interface.
func Named(iface string) *Module {
	m := &Module{intf: iface}
	l.Label(m, iface)
	l.Register(m, "outputFunc")
	// Default output is just the SSID when connected.
	m.Output(func(i Info) bar.Output {
		if i.Connected() {
			return outputs.Text(i.SSID)
		}
		return nil
	})
	return m
}

// Any constructs an instance of the wlan module that uses any available
// wireless interface, choosing the 'best' state from all available.
func Any() *Module {
	return Named("")
}

// Output configures a module to display the output of a user-defined function.
func (m *Module) Output(outputFunc func(Info) bar.Output) *Module {
	m.outputFunc.Set(outputFunc)
	return m
}

// Stream starts the module.
func (m *Module) Stream(s bar.Sink) {
	outputFunc := m.outputFunc.Get().(func(Info) bar.Output)
	nextOutputFunc, done := m.outputFunc.Subscribe()
	defer done()

	var linkSub *netlink.Subscription
	if m.intf == "" {
		linkSub = netlink.WithPrefix("wl")
	} else {
		linkSub = netlink.ByName(m.intf)
	}
	defer linkSub.Unsubscribe()

	info := handleUpdate(linkSub.Get())
	for {
		s.Output(outputFunc(info))
		select {
		case <-linkSub.C:
			info = handleUpdate(linkSub.Get())
		case <-nextOutputFunc:
			outputFunc = m.outputFunc.Get().(func(Info) bar.Output)
		}
	}
}

func handleUpdate(link netlink.Link) Info {
	info := Info{
		Name:  link.Name,
		State: link.State,
		IPs:   link.IPs,
	}
	info.Err = fillWifiInfo(&info)
	return info
}

func fillWifiInfo(info *Info) error {
	cl, err := wifi.New()
	if err != nil {
		return err
	}
	defer cl.Close()

	ifs, err := cl.Interfaces()
	if err != nil {
		return err
	}

	for _, intf := range ifs {
		if intf.Name == info.Name {
			info.AccessPointMAC = intf.HardwareAddr.String()
			info.Frequency = unit.Frequency(intf.Frequency) * unit.Megahertz

			bss, err := cl.BSS(intf)
			if err != nil {
				return err
			}
			info.SSID = bss.SSID

			sinf, err := cl.StationInfo(intf)
			if err != nil {
				return err
			}
			if len(sinf) == 0 {
				return nil
			}
			info.TransmitBitrate = unit.Datarate(sinf[0].TransmitBitrate) * unit.BitPerSecond
			info.ReceiveBitrate = unit.Datarate(sinf[0].ReceiveBitrate) * unit.BitPerSecond

			return nil
		}
	}
	return nil
}
