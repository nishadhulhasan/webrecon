package core

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"
)

type GraphqlEnumModule struct{}

func (m *GraphqlEnumModule) Name() string {
	return "GraphQL_Introspection"
}

func (m *GraphqlEnumModule) Execute(target string) (interface{}, error) {
	endpoints := []string{"/graphql", "/api/graphql", "/v1/graphql"}

	// The standard GraphQL Introspection query
	payload := []byte(`{"query":"\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n      }\n    }\n  "}`)

	client := &http.Client{Timeout: 10 * time.Second}
	findings := make(map[string]string)

	for _, endpoint := range endpoints {
		url := "http://" + target + endpoint

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		content := string(bodyBytes)

		// Check if the server responded with the schema mapping
		if resp.StatusCode == 200 && strings.Contains(content, "__schema") && strings.Contains(content, "queryType") {
			findings[endpoint] = "VULNERABLE: Full Introspection Query Allowed!"
		} else if resp.StatusCode == 200 || resp.StatusCode == 400 {
			// If it responds with GraphQL errors, the endpoint exists but might be secured
			if strings.Contains(content, "errors") || strings.Contains(content, "IntrospectionQuery") {
				findings[endpoint] = "GraphQL Endpoint Active (Introspection Disabled)"
			}
		}
	}

	if len(findings) == 0 {
		return []string{"No active GraphQL endpoints discovered"}, nil
	}

	return findings, nil
}
