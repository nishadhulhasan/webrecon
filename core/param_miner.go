package core

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type ParamMinerModule struct{}

func (m *ParamMinerModule) Name() string {
	return "Parameter_Miner"
}

func (m *ParamMinerModule) Execute(target string) (interface{}, error) {
	baseURL := "http://" + target + "/"
	client := &http.Client{Timeout: 5 * time.Second}

	// 1. Establish the baseline (normal request)
	baselineResp, err := client.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer baselineResp.Body.Close()

	baselineBytes, _ := io.ReadAll(baselineResp.Body)
	baselineLength := len(baselineBytes)
	baselineStatus := baselineResp.StatusCode

	// Small, high-probability wordlist for parameter discovery
	params := []string{"debug", "admin", "test", "id", "dir", "exec", "cmd", "file", "url", "redirect"}

	findings := make(map[string]string)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, param := range params {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			// Inject a canary value to see if it changes the response
			testURL := fmt.Sprintf("%s?%s=1337canary", baseURL, p)
			resp, err := client.Get(testURL)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(resp.Body)
			newLength := len(bodyBytes)

			// If the status code changes or the response length shifts significantly, we found a parameter
			if resp.StatusCode != baselineStatus || isSignificantlyDifferent(baselineLength, newLength) {
				mu.Lock()
				findings[p] = fmt.Sprintf("Active Parameter Detected (Status: %d, Length: %d)", resp.StatusCode, newLength)
				mu.Unlock()
			}
		}(param)
	}

	wg.Wait()

	if len(findings) == 0 {
		return []string{"No hidden parameters discovered on the base route"}, nil
	}

	return findings, nil
}

// Helper function to calculate if the response length changed enough to matter
func isSignificantlyDifferent(baseLen, newLen int) bool {
	diff := baseLen - newLen
	if diff < 0 {
		diff = -diff
	}
	// If the response length changes by more than 100 bytes, it's likely not just dynamic timestamp noise
	return diff > 100
}
