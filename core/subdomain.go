package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ReconModule is the interface all your 23 modules will implement
type ReconModule interface {
	Name() string
	Execute(target string) (interface{}, error)
}

type SubdomainModule struct{}

func (m *SubdomainModule) Name() string {
	return "Subdomain_Enum"
}

func (m *SubdomainModule) Execute(target string) (interface{}, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	// Deduplicate subdomains
	uniqueSubs := make(map[string]bool)
	var finalSubs []string
	for _, entry := range results {
		if !uniqueSubs[entry.NameValue] {
			uniqueSubs[entry.NameValue] = true
			finalSubs = append(finalSubs, entry.NameValue)
		}
	}

	return finalSubs, nil
}
