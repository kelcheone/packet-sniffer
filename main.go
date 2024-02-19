package main

import "fmt"

// "packet-sniffer/sniffer"

const (
	defaultSnapLen = 262144
)

func main() {
	ip := "204.79.197.200"

	domainName, err := Lookup(ip)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Println("Domain name: ", domainName)

	// sniffer.Start()
	//	Analyze()
	/*
		  fmt.Println("We are about to start")

			handle, err := pcap.OpenLive("lo", defaultSnapLen, true, pcap.BlockForever)
			if err != nil {
				panic(err)
			}

			defer handle.Close()

			if err := handle.SetBPFFilter("port 3030"); err != nil {
				panic(err)
			}

			packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()

			for pkt := range packets {
				fmt.Println(pkt)
			}*/
}
