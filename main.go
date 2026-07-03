package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"webrecontool/core"
	"webrecontool/utils"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <target.com>")
		os.Exit(1)
	}
	target := os.Args[1]

	fmt.Printf("[*] Initializing Reconnaissance on %s\n", target)
	startTime := time.Now()

	// Initialize the modules you want to run
	// Update this block inside your main.go
	// All active reconnaissance modules
	modules := []core.ReconModule{
		&core.PortScannerModule{}, // <-- NEW: Native TCP Port Scanner
		&core.SubdomainModule{},
		&core.HeadersModule{},
		&core.ResolverModule{},
		&core.SSLCheckerModule{},
		&core.WhoisAsnModule{},
		&core.TechStackModule{},
		&core.FuzzerModule{},
		&core.CrawlerModule{},
		&core.JSAnalyzerModule{},
		&core.WafDetectModule{},
		&core.CloudReconModule{},
		&core.DNSReconModule{},
		&core.RepoLeakModule{},
		&core.ParamMinerModule{},
		&core.CmsEnumModule{},
		&core.GraphqlEnumModule{},
		&core.BrokenLinksModule{},
		&core.Bypass403Module{},
	}
	results := make(map[string]interface{})
	var mu sync.Mutex // Mutex to prevent race conditions when writing to results map
	var wg sync.WaitGroup

	// Execute modules concurrently
	for _, mod := range modules {
		wg.Add(1)
		go func(m core.ReconModule) {
			defer wg.Done()

			log.Printf("[~] Starting module: %s...\n", m.Name())
			data, err := m.Execute(target)

			mu.Lock()
			if err != nil {
				log.Printf("[-] Module %s failed: %v\n", m.Name(), err)
				results[m.Name()] = fmt.Sprintf("Error: %v", err)
			} else {
				log.Printf("[+] Module %s completed.\n", m.Name())
				results[m.Name()] = data
			}
			mu.Unlock()

		}(mod)
	}

	wg.Wait()

	// Save results
	err := utils.SaveResults(target, results)
	if err != nil {
		log.Fatalf("[-] Failed to save results: %v\n", err)
	}

	fmt.Printf("[*] Recon finished in %v. Results saved to %s_report.json\n", time.Since(startTime), target)
}
