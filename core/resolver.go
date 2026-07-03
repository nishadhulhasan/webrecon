package core

import (
	"net"
	"strings"
)

type ResolverModule struct{}

func (m *ResolverModule) Name() string {
	return "DNS_Resolver"
}

type DNSReport struct {
	IPs   []string `json:"a_records,omitempty"`
	IPv6s []string `json:"aaaa_records,omitempty"`
	MX    []string `json:"mx_records,omitempty"`
	TXT   []string `json:"txt_records,omitempty"`
	CNAME string   `json:"cname,omitempty"`
}

func (m *ResolverModule) Execute(target string) (interface{}, error) {
	report := DNSReport{}

	// 1. Fetch A and AAAA records
	ips, err := net.LookupIP(target)
	if err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				report.IPs = append(report.IPs, ip.String())
			} else {
				report.IPv6s = append(report.IPv6s, ip.String())
			}
		}
	}

	// 2. Fetch MX records
	mxRecords, err := net.LookupMX(target)
	if err == nil {
		for _, mx := range mxRecords {
			report.MX = append(report.MX, mx.Host)
		}
	}

	// 3. Fetch TXT records (Useful for SPF/DMARC identification)
	txtRecords, err := net.LookupTXT(target)
	if err == nil {
		for _, txt := range txtRecords {
			report.TXT = append(report.TXT, txt)
		}
	}

	// 4. Fetch CNAME if it exists
	cname, err := net.LookupCNAME(target)
	if err == nil {
		// Clean trailing dot often returned by lookups
		cleanedCNAME := strings.TrimSuffix(cname, ".")
		if cleanedCNAME != target {
			report.CNAME = cleanedCNAME
		}
	}

	return report, nil
}
