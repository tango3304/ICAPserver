package main

import (
	"github.com/tango3304/go-icap-server/pkg"
	"log"
)

// #############################
// 主要な機能
// #############################
func main() {
	for {
		if err := pkg.StartTCPConnection(); err != nil {
			log.Printf("Error: %v", err)
			continue
		}
	}
}
