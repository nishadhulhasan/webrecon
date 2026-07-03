package core

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

type CrawlerModule struct{}

func (m *CrawlerModule) Name() string {
	return "Web_Spider"
}

func (m *CrawlerModule) Execute(target string) (interface{}, error) {
	targetURL := "http://" + target
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, err
	}

	internalLinks := make(map[string]bool) // Used for deduplication
	var links []string

	// Find every <a> tag in the HTML
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			parsed, err := url.Parse(href)
			if err == nil {
				// Check if the link is relative or belongs to the target domain
				if parsed.Host == "" || strings.Contains(parsed.Host, target) {
					cleanLink := parsed.Path
					if cleanLink != "" && cleanLink != "/" && !internalLinks[cleanLink] {
						internalLinks[cleanLink] = true
						links = append(links, cleanLink)
					}
				}
			}
		}
	})

	return links, nil
}
