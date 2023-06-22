package dnsweekend

import (
	"fmt"
	"testing"
)

func TestDecodeDNSNameSimple(t *testing.T) {
	input1 := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	expected1 := "www.example.com"
	result1, err := decodeDNSNameSimple(input1)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result1 != expected1 {
		t.Errorf("Expected %s, but got %s", expected1, result1)
	}

	// Test case 2: Empty DNS name
	input2 := []byte{0}
	expected2 := ""
	result2, err := decodeDNSNameSimple(input2)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result2 != expected2 {
		t.Errorf("Expected %s, but got %s", expected2, result2)
	}

	// Test case 3: Invalid DNS name (missing null terminator)
	input3 := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm'}
	_, err3 := decodeDNSNameSimple(input3)
	if err3 == nil {
		t.Error("Expected error, but got nil")
	}
}

func TestLookupDomain(t *testing.T) {
	domain1 := "example.com"
	ip1, err := LookupDomain(domain1)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	fmt.Printf("%s: %s\n", domain1, ip1)

	domain2 := "google.com"
	ip2, err := LookupDomain(domain2)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	fmt.Printf("%s: %s\n", domain2, ip2)

	domain3 := "twitter.com"
	ip3, err := LookupDomain(domain3)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	fmt.Printf("%s: %s\n", domain3, ip3)
}
