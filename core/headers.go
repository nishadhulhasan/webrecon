package core

import (
	"net/http"
	"time"
)

type HeadersModule struct{}

func (m *HeadersModule) Name() string {
	return "Security_Headers"
}

func (m *HeadersModule) Execute(target string) (interface{}, error) {
	url := "https://" + target

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	securityHeaders := []string{
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Content-Security-Policy",
		"X-XSS-Protection",
	}

	findings := make(map[string]string)

	for _, header := range securityHeaders {
		val := resp.Header.Get(header)
		if val == "" {
			findings[header] = "MISSING"
		} else {
			findings[header] = val
		}
	}

	return findings, nil
}
