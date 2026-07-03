package core

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type PortScannerModule struct{}

func (m *PortScannerModule) Name() string {
	return "Fast_Port_Scanner"
}

func (m *PortScannerModule) Execute(target string) (interface{}, error) {
	// A curated list of high-value ports (Web, DB, SSH, RDP, standard dev ports)
	ports := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
		1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
		8888, 9000, 9090, 9200, 9443, 10000, 27017,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var openPorts []string

	// Fire a goroutine for every single port simultaneously
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			address := fmt.Sprintf("%s:%d", target, p)

			// A 2-second timeout ensures the scan doesn't hang forever on firewalled/filtered ports
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)

			if err == nil {
				// If the connection succeeds, the port is open
				mu.Lock()
				openPorts = append(openPorts, fmt.Sprintf("Port %d: OPEN", p))
				mu.Unlock()
				conn.Close()
			}
		}(port)
	}

	// Wait for all port connections to either succeed or timeout
	wg.Wait()

	if len(openPorts) == 0 {
		return []string{"No common open ports detected (or heavily firewalled)"}, nil
	}

	return openPorts, nil
}
