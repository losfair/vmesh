package main

import (
	"encoding/json"
	"flag"
	"github.com/golang/protobuf/proto"
	"github.com/losfair/vmesh"
	"github.com/losfair/vmesh/protocol"
	"io/ioutil"
	"log"
	"syscall"
	"time"
)

func main() {
	configPathFlag := flag.String("config", "config.json", "Path to configuration")
	debugFlag := flag.Bool("debug", false, "Enable debug logging")
	tableFlag := flag.String("table", "", "Path to periodically dump the routing table to")
	dropPermissionsFlag := flag.Bool("drop-permissions", false, "Drop permissions from root to nobody")
	initialDCFlag := flag.String("initial-dc", "", "Path to initial distributed config")
	flag.Parse()

	var config vmesh.NodeConfig

	configRaw, err := ioutil.ReadFile(*configPathFlag)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(configRaw, &config); err != nil {
		log.Fatal(err)
	}

	vmesh.EnableDebug = *debugFlag

	node, err := vmesh.NewNode(&config)
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

	if len(*initialDCFlag) > 0 {
		dcRaw, err := ioutil.ReadFile(*initialDCFlag)
		if err != nil {
			log.Println("Warning: Unable to read initial distributed config")
		} else {
			var dc protocol.DistributedConfig
			if err := proto.Unmarshal(dcRaw, &dc); err != nil {
				log.Println("Warning: Unable to parse initial distributed config")
			} else {
				if err := node.UpdateDistributedConfig(&dc); err != nil {
					log.Println("Failed to apply initial distributed config:", err)
				}
			}
		}
	}

	node.ConnectToAllPeers()

	err = node.Run()
	log.Fatal(err)
}
