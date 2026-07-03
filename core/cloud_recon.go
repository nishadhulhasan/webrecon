package core

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CloudReconModule struct{}

func (m *CloudReconModule) Name() string {
	return "Cloud_S3_Recon"
}

func (m *CloudReconModule) Execute(target string) (interface{}, error) {
	// Strip out TLD for bucket permutation (e.g., example.com -> example)
	baseParts := strings.Split(target, ".")
	if len(baseParts) == 0 {
		return nil, fmt.Errorf("invalid target format")
	}
	baseName := baseParts[0]

	permutations := []string{
		baseName,
		baseName + "-prod",
		baseName + "-dev",
		baseName + "-staging",
		baseName + "-assets",
		baseName + "-backup",
		baseName + "-public",
	}

	client := &http.Client{Timeout: 5 * time.Second}
	findings := make(map[string]string)

	for _, perm := range permutations {
		bucketURL := fmt.Sprintf("https://%s.s3.amazonaws.com", perm)
		resp, err := client.Get(bucketURL)
		if err != nil {
			continue
		}

		// 404 means doesn't exist. 403 means exists but private. 200 means PUBLIC!
		if resp.StatusCode == 200 {
			findings[bucketURL] = "PUBLIC (Vulnerable to data leak!)"
		} else if resp.StatusCode == 403 {
			findings[bucketURL] = "Exists (Private)"
		}
		resp.Body.Close()
	}

	if len(findings) == 0 {
		return []string{"No obvious S3 buckets found matching base domain"}, nil
	}

	return findings, nil
}
