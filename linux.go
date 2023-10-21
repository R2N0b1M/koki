//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
)

func KokiStart(receiver chan []byte, sender chan []byte, config Config) {
	fmt.Println("linux version")
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(HostToNetShort(syscall.ETH_P_ALL)))
	if err != nil {
		syscall.Close(fd)
		panic(err)
	}
	err = syscall.BindToDevice(fd, config.Device)
	if err != nil {
		syscall.Close(fd)
		panic(err)
	}
	iface, err := net.InterfaceByName(config.Device)
	if err != nil {
		syscall.Close(fd)
		panic(err)
	}
	data := make([]byte, 128)
	go func() {
		for {
			pkt := <-sender
			err := syscall.Sendto(fd, pkt, 0, &syscall.SockaddrLinklayer{
				Protocol: syscall.ETH_P_ALL,
				Ifindex:  iface.Index,
			})
			if err != nil {
				fmt.Println(err)
			}
		}
	}()
	for {
		syscall.Recvfrom(fd, data, 0)
		copyData := make([]byte, len(data))
		copy(copyData, data)
		receiver <- copyData
	}
}
