//go:build scion && cgo && (linux || darwin) && !android && !ios

package scion

import (
	"fmt"

	"github.com/netbirdio/netbird/shared/scionaddr"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

func pathFitsMTU(local, remote scionaddr.Address, path snet.DataplanePath, interfaceMTU, pathMTU uint16) (bool, error) {
	size, err := serializedPacketSize(local, remote, path, interfaceMTU)
	return size <= int(pathMTU), err
}

func serializedPacketSize(local, remote scionaddr.Address, path snet.DataplanePath, interfaceMTU uint16) (int, error) {
	source, err := addr.ParseAddr(fmt.Sprintf("%s,%s", local.IA, local.Host.Addr()))
	if err != nil {
		return 0, err
	}
	destination, err := addr.ParseAddr(fmt.Sprintf("%s,%s", remote.IA, remote.Host.Addr()))
	if err != nil {
		return 0, err
	}
	packet := snet.Packet{PacketInfo: snet.PacketInfo{
		Source:      source,
		Destination: destination,
		Path:        path,
		Payload: snet.UDPPayload{
			SrcPort: local.Host.Port(), DstPort: remote.Host.Port(),
			Payload: make([]byte, int(interfaceMTU)+32),
		},
	}}
	if err := packet.Serialize(); err != nil {
		return 0, err
	}
	return len(packet.Bytes), nil
}
