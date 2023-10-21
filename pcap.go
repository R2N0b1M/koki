//go:build !linux

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket/pcap"
)

func KokiStart(receiver chan []byte, sender chan []byte, config Config) {
	log.Println("pcap version")
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		fmt.Println(device.Name, device.Description)
	}
	handle, err := pcap.OpenLive(config.Device, 128, true, time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}

	var filter string = "ip and tcp and tcp[13] & 2 != 0"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()
	go func() {
		for {
			pkt := <-sender
			if err = handle.WritePacketData(pkt); err != nil {
				log.Fatal(err)
			}
		}
	}()
	for {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			continue
		}
		receiver <- data
	}
}
