package main

import (
	"fmt"
	"log"
	"net"
)

func Lookup(ipAdress string) (string, error) {
	ip := net.ParseIP(ipAdress)

	if ip == nil {
		log.Println("Invalid IP address")
		return "", fmt.Errorf("Invalid IP address: %s", ip)
	}

	names, err := net.LookupAddr(ipAdress)
	if err != nil {
		return "", fmt.Errorf("reverse DNS lookup failed: %w", err)
	}

	if len(names) > 0 {
		return names[0], nil
	} else {
		return "", fmt.Errorf("no domain name found for IP Address: %s", ipAdress)
	}
}
