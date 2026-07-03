package core

import (
	"net/http"
	"sync"
	"time"
)

type FuzzerModule struct{}

func (m *FuzzerModule) Name() string {
	return "Directory_Fuzzer"
}

func (m *FuzzerModule) Execute(target string) (interface{}, error) {
	// A small, high-impact wordlist for testing.
	// In production, you would read this from a seclists.txt file.
	wordlist := []string{
		"admin", "login", "api", "v1", "v2", "staging",
		"dev", "test", "backup", "config", ".git", ".env",
	}

	baseURL := "http://" + target + "/"
	results := make(map[string]int) // Maps the discovered path to its HTTP status code

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Worker pool setup
	concurrency := 5 // Limit to 5 concurrent HTTP requests to avoid rate limits
	paths := make(chan string, len(wordlist))

	// Start the workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 5 * time.Second}

			// Workers continuously pull paths from the channel until it's closed
			for path := range paths {
				url := baseURL + path
				resp, err := client.Get(url)
				if err != nil {
					continue // Skip on timeout/connection error
				}

				// Record interesting status codes (e.g., 200 OK, 401 Auth Required, 403 Forbidden)
				if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
					mu.Lock()
					results["/"+path] = resp.StatusCode
					mu.Unlock()
				}
				resp.Body.Close()
			}
		}()
	}

	// Send jobs into the channel
	for _, word := range wordlist {
		paths <- word
	}
	close(paths) // Close channel to signal workers to stop when queue is empty

	// Wait for all workers to finish
	wg.Wait()

	return results, nil
}
