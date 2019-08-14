package main

import (
	"encoding/json"
	"flag"
	"github.com/losfair/vnet"
	"io/ioutil"
	"log"
	"syscall"
	"time"
)

func main() {
	configPathFlag := flag.String("config", "config.json", "Path to configuration")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	tableFlag := flag.String("table", "", "Path to periodically dump the routing table to")
	dropPermissionsFlag := flag.Bool("drop_permissions", false, "Drop permissions from root to nobody")
	flag.Parse()

	var config vnet.NodeConfig

	configRaw, err := ioutil.ReadFile(*configPathFlag)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(configRaw, &config); err != nil {
		log.Fatal(err)
	}

	vnet.EnableDebug = *debugFlag

	node, err := vnet.NewNode(&config)
	if err != nil {
		log.Fatal(err)
	}

	// Drop permissions after NewNode() which may initialize the tun device
	if *dropPermissionsFlag {
		if err := syscall.Setgid(65534); err != nil {
			log.Fatalln("setgid failed:", err)
		}
		if err := syscall.Setuid(65534); err != nil {
			log.Fatalln("setuid failed:", err)
		}
	}

	if len(*tableFlag) > 0 {
		go func() {
			for {
				data := node.BuildPrintableRoutingTable()
				_ = ioutil.WriteFile(*tableFlag, []byte(data), 0644)
				time.Sleep(10 * time.Second)
			}
		}()
	}

	node.ConnectToAllPeers()

	err = node.Run()
	log.Fatal(err)
}
