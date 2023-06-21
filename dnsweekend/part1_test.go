package dnsweekend

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestDNSHeaderToBytes(t *testing.T) {
	header := DNSHeader{
		ID:      0x1314,
		Flags:   0,
		QDCount: 1,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	bytes := header.toBytes()

	expectedBytes := []byte{
		0x13, 0x14,
		0x00, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}

	if !reflect.DeepEqual(bytes, expectedBytes) {
		t.Errorf("Expected %v, but got %v", expectedBytes, bytes)
	}
}

func TestDNSHeaderSetFlags(t *testing.T) {
	header := DNSHeader{}

	header.setFlags(0, 0, 0, 0, 1, 0, 0, 0)
	expectedFlags := uint16(0b100000000) // Binary: 1000111111111111
	if header.Flags != expectedFlags {
		t.Errorf("Expected Flags to be %v, but got %v", expectedFlags, header.Flags)
	}
}

func TestEncodeDNSName(t *testing.T) {
	tests := []struct {
		domain       string
		expectedName []byte
	}{
		{
			domain:       "www.google.com",
			expectedName: []byte{3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			domain:       "example.com",
			expectedName: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			domain:       "dnsweekend.com",
			expectedName: []byte{10, 'd', 'n', 's', 'w', 'e', 'e', 'k', 'e', 'n', 'd', 3, 'c', 'o', 'm', 0},
		},
	}

	for _, test := range tests {
		actualName := encodeDNSName(test.domain)
		if !reflect.DeepEqual(actualName, test.expectedName) {
			t.Errorf("Expected %v, but got %v", test.expectedName, actualName)
		}
	}
}

func TestDNSQuestionToBytes(t *testing.T) {
	question := DNSQuestion{
		Name:  []byte{3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm'},
		Type:  1,
		Class: 1,
	}

	bytes := question.toBytes()

	expectedBytes := []byte{
		3, 'w', 'w', 'w',
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		3, 'c', 'o', 'm',
		0, 1,
		0, 1,
	}

	if !reflect.DeepEqual(bytes, expectedBytes) {
		t.Errorf("Expected %v, but got %v", expectedBytes, bytes)
	}
}

func TestSendQuery(t *testing.T) {
	domain := "www.example.com"
	resp, err := SendQuery(domain, "8.8.8.8:53", A)
	if err != nil {
		panic(err)
	}
	str := hex.EncodeToString(resp)

	// Run `sudo tcpdump -ni any port 53`
	// And check that the output is in line with
	// 08:31:19.676059 IP 192.168.1.173.62752 > 8.8.8.8.53: 45232+ A? www.example.com. (33)
	// 08:31:19.694678 IP 8.8.8.8.53 > 192.168.1.173.62752: 45232 1/0/0 A 93.184.216.34 (49)
	t.Logf("%s\n", str)
}
