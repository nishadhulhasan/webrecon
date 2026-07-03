package core

import (
	"io"
	"net/http"
	"strings"
	"time"
)

type WafDetectModule struct{}

func (m *WafDetectModule) Name() string {
	return "WAF_Detection"
}

func (m *WafDetectModule) Execute(target string) (interface{}, error) {
	// We send a harmless but anomalous query string that often triggers basic WAF rules
	url := "http://" + target + "/?id=../../etc/passwd"

	req, _ := http.NewRequest("GET", url, nil)
	// Spoof a slightly unusual user agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebRecon/1.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "Connection failed (Potential WAF Drop)", nil
	}
	defer resp.Body.Close()

	wafSignatures := make(map[string]bool)

	// 1. Passive Header Inspection
	headers := map[string]string{
		"Server":      resp.Header.Get("Server"),
		"Cf-Ray":      resp.Header.Get("CF-RAY"),
		"X-Sucuri-Id": resp.Header.Get("X-Sucuri-ID"),
		"X-Amz-Cf-Id": resp.Header.Get("X-Amz-Cf-Id"),
	}

	serverHeader := strings.ToLower(headers["Server"])
	if strings.Contains(serverHeader, "cloudflare") {
		wafSignatures["Cloudflare"] = true
	} else if strings.Contains(serverHeader, "imperva") || strings.Contains(serverHeader, "incapsula") {
		wafSignatures["Imperva / Incapsula"] = true
	} else if strings.Contains(serverHeader, "awselb") || headers["X-Amz-Cf-Id"] != "" {
		wafSignatures["AWS WAF / CloudFront"] = true
	} else if headers["X-Sucuri-Id"] != "" {
		wafSignatures["Sucuri"] = true
	}

	// 2. Active Body Inspection (If blocked)
	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			bodyString := strings.ToLower(string(bodyBytes))
			if strings.Contains(bodyString, "attention required!") || strings.Contains(bodyString, "cloudflare") {
				wafSignatures["Cloudflare (Active Block)"] = true
			}
			if strings.Contains(bodyString, "access denied") && strings.Contains(bodyString, "amazon") {
				wafSignatures["AWS WAF (Active Block)"] = true
			}
		}
	}

	var detectedWAFs []string
	for waf := range wafSignatures {
		detectedWAFs = append(detectedWAFs, waf)
	}

	if len(detectedWAFs) == 0 {
		return "No known WAF signatures detected", nil
	}

	return detectedWAFs, nil
}
