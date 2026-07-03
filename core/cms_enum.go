package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type CmsEnumModule struct{}

func (m *CmsEnumModule) Name() string {
	return "CMS_User_Enum"
}

func (m *CmsEnumModule) Execute(target string) (interface{}, error) {
	url := "http://" + target + "/wp-json/wp/v2/users"
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return []string{"No exposed WordPress REST API found"}, nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the JSON response to extract usernames
	var users []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &users); err != nil {
		// If it's 200 OK but not JSON, it might be blocked by a plugin
		if strings.Contains(string(bodyBytes), "rest_user_cannot_view") {
			return []string{"WP API exists but user enumeration is blocked"}, nil
		}
		return []string{"Failed to parse WP REST API response"}, nil
	}

	var foundUsers []string
	for _, user := range users {
		if name, ok := user["name"].(string); ok {
			if slug, ok := user["slug"].(string); ok {
				foundUsers = append(foundUsers, fmt.Sprintf("User: %s (Slug: %s)", name, slug))
			}
		}
	}

	if len(foundUsers) == 0 {
		return []string{"WP API reachable, but no users extracted"}, nil
	}

	return foundUsers, nil
}
