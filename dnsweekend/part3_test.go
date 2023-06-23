package dnsweekend

import (
	"fmt"
	"testing"
)

func TestResolve(t *testing.T) {
	domain1 := "google.com"
	ip1, err := Resolve(domain1, A)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	fmt.Printf("%s: %s\n", domain1, ip1)

	domain2 := "facebook.com"
	ip2, err := Resolve(domain2, A)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	fmt.Printf("%s: %s\n", domain2, ip2)
}
