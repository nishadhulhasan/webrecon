package core

import (
	"net"
	"strings"
)

type DNSReconModule struct{}

func (m *DNSReconModule) Name() string {
	return "DNS_Spoofing_Check"
}

func (m *DNSReconModule) Execute(target string) (interface{}, error) {
	txtRecords, err := net.LookupTXT(target)
	if err != nil {
		return nil, err
	}

	findings := make(map[string]string)
	hasSPF := false
	hasDMARC := false

	// Check SPF configuration
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			hasSPF = true
			if strings.Contains(record, "~all") {
				findings["SPF"] = "Soft fail (~all) - Weak protection"
			} else if strings.Contains(record, "-all") {
				findings["SPF"] = "Hard fail (-all) - Secure"
			} else if strings.Contains(record, "?all") {
				findings["SPF"] = "Neutral (?all) - Vulnerable to spoofing"
			} else if strings.Contains(record, "+all") {
				findings["SPF"] = "Allow all (+all) - HIGHLY Vulnerable!"
			} else {
				findings["SPF"] = "Custom configuration found: " + record
			}
		}
	}
	if !hasSPF {
		findings["SPF"] = "Missing entirely - Vulnerable to spoofing"
	}

	// Check DMARC configuration (Requires prefixing _dmarc to the domain)
	dmarcTarget := "_dmarc." + target
	dmarcRecords, _ := net.LookupTXT(dmarcTarget)
	for _, record := range dmarcRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			hasDMARC = true
			if strings.Contains(record, "p=none") {
				findings["DMARC"] = "Monitoring only (p=none) - Spoofable if SPF fails"
			} else if strings.Contains(record, "p=quarantine") || strings.Contains(record, "p=reject") {
				findings["DMARC"] = "Secure (p=quarantine or p=reject)"
			} else {
				findings["DMARC"] = "Custom configuration found: " + record
			}
		}
	}
	if !hasDMARC {
		findings["DMARC"] = "Missing entirely"
	}

	return findings, nil
}
