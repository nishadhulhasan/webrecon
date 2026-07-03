package core

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

type JSAnalyzerModule struct{}

func (m *JSAnalyzerModule) Name() string {
	return "JS_Analyzer"
}

func (m *JSAnalyzerModule) Execute(target string) (interface{}, error) {
	baseURL := "http://" + target
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsURLs []string
	// Find all <script src="..."> tags
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists && strings.HasSuffix(src, ".js") {
			if strings.HasPrefix(src, "http") {
				jsURLs = append(jsURLs, src)
			} else if strings.HasPrefix(src, "/") {
				jsURLs = append(jsURLs, baseURL+src)
			} else {
				jsURLs = append(jsURLs, baseURL+"/"+src)
			}
		}
	})

	findings := make(map[string][]string)

	// Regex patterns for juicy information
	endpointRegex := regexp.MustCompile(`(?i)(?:api/v[0-9]|/api/[a-z0-9_-]+)`)
	tokenRegex := regexp.MustCompile(`(?i)(?:bearer\s+[A-Za-z0-9\-\._~+\/]+=*)`)

	// Scan each discovered JS file
	for _, jsURL := range jsURLs {
		jsResp, err := client.Get(jsURL)
		if err != nil {
			continue
		}

		bodyBytes, err := io.ReadAll(jsResp.Body)
		jsResp.Body.Close()
		if err != nil {
			continue
		}

		content := string(bodyBytes)

		endpoints := endpointRegex.FindAllString(content, -1)
		tokens := tokenRegex.FindAllString(content, -1)

		if len(endpoints) > 0 || len(tokens) > 0 {
			var fileFindings []string
			fileFindings = append(fileFindings, endpoints...)
			fileFindings = append(fileFindings, tokens...)

			// Deduplicate findings for this specific file
			unique := make(map[string]bool)
			for _, item := range fileFindings {
				if !unique[item] {
					findings[jsURL] = append(findings[jsURL], item)
					unique[item] = true
				}
			}
		}
	}

	if len(findings) == 0 {
		return []string{"No obvious API endpoints or secrets found in JS"}, nil
	}

	return findings, nil
}
