package core

import (
	"io"
	"net/http"
	"strings"
	"time"
)

type TechStackModule struct{}

func (m *TechStackModule) Name() string {
	return "Tech_Stack_Fingerprint"
}

func (m *TechStackModule) Execute(target string) (interface{}, error) {
	url := "http://" + target
	client := &http.Client{
		Timeout: 10 * time.Second,
		// Do not follow redirects to capture the initial server headers
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	technologies := make(map[string]bool)

	// 1. Analyze Headers
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		technologies["Server: "+serverHeader] = true
	}

	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		technologies["X-Powered-By: "+xPoweredBy] = true
	}

	xAspNetVersion := resp.Header.Get("X-AspNet-Version")
	if xAspNetVersion != "" {
		technologies["ASP.NET"] = true
	}

	// 2. Analyze HTML Body for common framework signatures
	bodyBytes, err := io.ReadAll(resp.Body)
	if err == nil {
		bodyString := strings.ToLower(string(bodyBytes))

		if strings.Contains(bodyString, "wp-content/") || strings.Contains(bodyString, "wp-includes/") {
			technologies["WordPress"] = true
		}
		if strings.Contains(bodyString, "react-root") || strings.Contains(bodyString, "data-reactroot") {
			technologies["React.js"] = true
		}
		if strings.Contains(bodyString, "ng-app") || strings.Contains(bodyString, "ng-controller") {
			technologies["AngularJS"] = true
		}
		if strings.Contains(bodyString, "laravel_session") {
			technologies["Laravel"] = true
		}
	}

	// Convert map to a clean array for JSON output
	var detectedTech []string
	for tech := range technologies {
		detectedTech = append(detectedTech, tech)
	}

	if len(detectedTech) == 0 {
		return []string{"No obvious tech stack signatures detected"}, nil
	}

	return detectedTech, nil
}
