package core

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

type BrokenLinksModule struct{}

func (m *BrokenLinksModule) Name() string {
	return "Broken_Link_Hijacking"
}

func (m *BrokenLinksModule) Execute(target string) (interface{}, error) {
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

	var externalLinks []string
	uniqueLinks := make(map[string]bool)

	// Extract all links
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists && strings.HasPrefix(href, "http") {
			parsed, err := url.Parse(href)
			if err == nil && !strings.Contains(parsed.Host, target) {
				if !uniqueLinks[href] {
					uniqueLinks[href] = true
					externalLinks = append(externalLinks, href)
				}
			}
		}
	})

	findings := make(map[string]string)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Check external links for 404 Not Found (vulnerable to takeover)
	for _, extLink := range externalLinks {
		wg.Add(1)
		go func(link string) {
			defer wg.Done()

			// Use a quick HEAD request instead of GET to save bandwidth
			req, _ := http.NewRequest("HEAD", link, nil)
			extClient := &http.Client{Timeout: 5 * time.Second}
			extResp, err := extClient.Do(req)

			if err != nil {
				return
			}
			defer extResp.Body.Close()

			if extResp.StatusCode == 404 {
				mu.Lock()
				findings[link] = "404 Not Found (Potential Hijacking Candidate!)"
				mu.Unlock()
			}
		}(extLink)
	}

	wg.Wait()

	if len(findings) == 0 {
		return []string{"No broken external links discovered"}, nil
	}

	return findings, nil
}
