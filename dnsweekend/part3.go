// Package dnsweekend https://implement-dns.wizardzines.com/
package dnsweekend

import (
	"bytes"
	"fmt"
)

// Resolve a domain name to an IP address using DNS recursion
// (i.e. keep asking other DNS servers until we get an answer)
// This is a very simple implementation of a DNS resolver
// (it doesn't support caching, timeouts, retries, etc.)
// but it's enough to resolve most domain names to IP addresses
// (including the root nameservers)
func Resolve(domain string, recordType RecordType) (string, error) {
	// From https://www.iana.org/domains/root/servers
	// You can use any of these servers to resolve any domain
	nameserver := "192.33.4.12"

	for {
		fmt.Printf("Querying %s for domain %s\n", nameserver, domain)
		resp, _ := SendQuery(domain, nameserver+":53", recordType)
		respReader := bytes.NewReader(resp)
		dnsPacket := parseDNSPacket(respReader)

		// If we got an answer, return it
		// (we only care about the first answer)
		for _, answer := range dnsPacket.Answers {
			if answer.Type == uint16(A) {
				ip := answer.data
				return dataIPtoString(ip), nil
			}
		}
		// If we didn't get an answer, try to find a nameserver
		// and use that instead of the default nameserver
		var newNameserver string
		for _, additional := range dnsPacket.Additionals {
			if additional.Type == uint16(A) {
				newNameserver = dataIPtoString(additional.data)
				if len(newNameserver) > 0 {
					break
				}
			}
		}
		if newNameserver != "" {
			nameserver = newNameserver
			continue
		}
		// If we didn't find a nameserver, try to find an authority
		// and use that instead of the default nameserver (and loop)
		// until we find an IP address for a nameserver
		for _, authority := range dnsPacket.Authorities {
			if authority.Type == uint16(NS) {
				nameserverDomain := string(authority.data)
				nameserver, _ = Resolve(nameserverDomain, A)
				break
			}
		}

		panic("something went wrong")
	}
}
