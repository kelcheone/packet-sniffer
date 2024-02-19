package sniffer

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	DevName = "wlp1s0"
	Found   = false
)

func Start() {
	file, err := os.OpenFile("packet.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to log to file %v \n", err)
	}
	defer file.Close()

	logger := log.New(file, "", log.LstdFlags)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		logger.Fatalf("Unable to fetch network devices: %v\n", err)
	}
	for _, ifDev := range devices {
		if ifDev.Name == DevName {
			Found = true
		}
	}
	if !Found {
		logger.Fatalf("Desired device not found")
	}

	handle, err := pcap.OpenLive(DevName, 1600, false, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		logger.Fatalf("Unable to open handle on the device: %v", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp and port 443"); err != nil {
		logger.Fatalf("Failed to set BPF filter: %v", err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		logger.Println(packet)
		//		fmt.Println(packet)
	}
}
