package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func Analyze() {
	file, err := os.Open("packet.log")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	packetRegex := regexp.MustCompile(
		`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) PACKET: (\d+) bytes, wire length (\d+) cap length (\d+) @ (.+) - Layer 1 \(\d+ bytes\) = Ethernet\s+{Contents=\[\.\.14\.\.\] Payload=\[\.\.(\d+)\.\.\] SrcMAC=(\S+) DstMAC=(\S+) EthernetType=IPv4 Length=\d+}\s+- Layer 2 \(\d+ bytes\) = IPv4\s+{Contents=\[\.\.20\.\.\] Payload=\[\.\.(\d+)\.\.\] Version=4 IHL=5 TOS=\d+ Length=\d+ Id=\d+ Flags=DF FragOffset=\d+ TTL=\d+ Protocol=TCP Checksum=\d+ SrcIP=(\S+) DstIP=(\S+) Options=\[\] Padding=\[\]}\s+- Layer 3 \(\d+ bytes\) = TCP\s+{Contents=\[\.\.32\.\.\] Payload=\[\.\.(\d+)\.\.\] SrcPort=(\d+) DstPort=(\d+)\(https\) Seq=\d+ Ack=\d+ DataOffset=\d+ FIN=false SYN=false RST=false PSH=(true|false) ACK=(true|false) URG=false ECE=false CWR=false NS=false Window=\d+ Checksum=\d+ Urgent=\d+ Options=\[.+\] Padding=\[\]}$`,
	)

	for scanner.Scan() {
		line := scanner.Text()
		match := packetRegex.FindStringSubmatch(line)
		if len(match) > 0 {
			fmt.Println("Packet details:")
			fmt.Printf("Time: %s\n", match[1])
			fmt.Printf("Total bytes: %s\n", match[2])
			fmt.Printf("Wire length: %s\n", match[3])
			fmt.Printf("Cap length: %s\n", match[4])
			fmt.Printf("SrcMAC: %s\n", match[7])
			fmt.Printf("DstMAC: %s\n", match[8])
			fmt.Printf("SrcIP: %s\n", match[11])
			fmt.Printf("DstIP: %s\n", match[12])
			fmt.Printf("SrcPort: %s\n", match[15])
			fmt.Printf("DstPort: %s\n", match[16])
			fmt.Printf("PSH: %s\n", match[17])
			fmt.Printf("ACK: %s\n", match[18])
			fmt.Println(strings.Repeat("-", 20))
		}
	}
}
