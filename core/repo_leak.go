package core

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RepoLeakModule struct{}

func (m *RepoLeakModule) Name() string {
	return "Repo_Leak_Checker"
}

func (m *RepoLeakModule) Execute(target string) (interface{}, error) {
	baseURL := "http://" + target

	// Critical files that often leak source code, database passwords, or API keys
	payloads := []string{
		"/.git/config",
		"/.env",
		"/.svn/entries",
		"/.DS_Store",
		"/docker-compose.yml",
		"/config.php.bak",
	}

	findings := make(map[string]string)
	var wg sync.WaitGroup
	var mu sync.Mutex

	client := &http.Client{Timeout: 5 * time.Second}

	for _, payload := range payloads {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()

			url := baseURL + path
			resp, err := client.Get(url)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Check if the file actually exists and isn't just a 404/403 page masquerading as 200 OK
			if resp.StatusCode == 200 {
				bodyBytes, _ := io.ReadAll(resp.Body)
				content := string(bodyBytes)

				// Verify file signatures to reduce false positives
				isVulnerable := false
				if strings.HasSuffix(path, "/.git/config") && strings.Contains(content, "[core]") {
					isVulnerable = true
				} else if strings.HasSuffix(path, "/.env") && (strings.Contains(content, "DB_") || strings.Contains(content, "API_")) {
					isVulnerable = true
				} else if !strings.Contains(content, "<html") {
					// Generic check: if it's 200 OK but not an HTML document, it's likely a real leak
					isVulnerable = true
				}

				if isVulnerable {
					mu.Lock()
					findings[url] = "EXPOSED SECRETS FOUND!"
					mu.Unlock()
				}
			}
		}(payload)
	}

	wg.Wait()

	if len(findings) == 0 {
		return []string{"No exposed repositories or .env files detected"}, nil
	}

	return findings, nil
}
