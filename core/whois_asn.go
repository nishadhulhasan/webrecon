package core

import (
	"strings"

	"github.com/likexian/whois"
)

type WhoisAsnModule struct{}

func (m *WhoisAsnModule) Name() string {
	return "Whois_Registry"
}

type WhoisReport struct {
	Registrar  string   `json:"registrar,omitempty"`
	NameServer []string `json:"name_servers,omitempty"`
	RawLength  int      `json:"raw_length"`
}

func (m *WhoisAsnModule) Execute(target string) (interface{}, error) {
	// Query public whois servers directly
	rawOutput, err := whois.Whois(target)
	if err != nil {
		return nil, err
	}

	report := WhoisReport{
		RawLength: len(rawOutput),
	}

	// Basic textual parsing since WHOIS lacks standard JSON layouts
	lines := strings.Split(rawOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lowered := strings.ToLower(line)

		if strings.HasPrefix(lowered, "registrar:") {
			report.Registrar = strings.TrimSpace(line[10:])
		}
		if strings.HasPrefix(lowered, "name server:") {
			ns := strings.ToLower(strings.TrimSpace(line[12:]))
			report.NameServer = append(report.NameServer, ns)
		}
	}

	return report, nil
}
