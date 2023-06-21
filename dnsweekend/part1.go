// Package dnsweekend https://implement-dns.wizardzines.com/
package dnsweekend

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
)

// RecordType is a 16 bit field
type RecordType uint16

const (
	A    RecordType = 1  // A is a host address
	NS   RecordType = 2  // NS is an authoritative name server
	AAAA RecordType = 28 // AAAA is a IPv6 host address
)

// RecordClass is a 16 bit field
type RecordClass uint16

const (
	IN RecordClass = 1 // IN for Internet
)

// DNSHeader (12 bytes)
type DNSHeader struct {
	ID      uint16 // ID
	Flags   uint16 // Flags (QR - 1 bit, Opcode - 4 bits, AA - 1 bit, TC - 1 bit, RD - 1 bit, RA - 1 bit, Z - 3 bits, RCODE - 4 bits)
	QDCount uint16 // Question Count
	ANCount uint16 // Answer Count
	NSCount uint16 // Name Server Count
	ARCount uint16 // Additional Record Count
}

// DNSQuestion (variable length)
type DNSQuestion struct {
	Name  []byte // Name
	Type  uint16 // Type (A, AAAA, MX, NS, etc.)
	Class uint16 // Class (IN, CH, HS, etc.)
}

func (h *DNSHeader) toBytes() []byte {
	bytes := make([]byte, 12)
	binary.BigEndian.PutUint16(bytes[0:2], h.ID)
	binary.BigEndian.PutUint16(bytes[2:4], h.Flags)
	binary.BigEndian.PutUint16(bytes[4:6], h.QDCount)
	binary.BigEndian.PutUint16(bytes[6:8], h.ANCount)
	binary.BigEndian.PutUint16(bytes[8:10], h.NSCount)
	binary.BigEndian.PutUint16(bytes[10:12], h.ARCount)
	return bytes
}

func (h *DNSHeader) setFlags(qr uint16, opcode uint16, aa uint16, tc uint16, rd uint16, ra uint16, z uint16, rcode uint16) {
	const (
		QRBit     = 15
		OpCodeBit = 11
		AAbit     = 10
		TCbit     = 9
		RDbit     = 8
		RAbit     = 7
		Zbit      = 4
	)

	h.Flags = (qr << QRBit) |
		(opcode << OpCodeBit) |
		(aa << AAbit) |
		(tc << TCbit) |
		(rd << RDbit) |
		(ra << RAbit) |
		(z << Zbit) |
		rcode
}

func (q *DNSQuestion) toBytes() []byte {
	nameLength := len(q.Name)
	questionSize := nameLength + 4 // 4 bytes for Type and Class
	bytes := make([]byte, questionSize)

	copy(bytes, q.Name)
	binary.BigEndian.PutUint16(bytes[nameLength:], q.Type)
	binary.BigEndian.PutUint16(bytes[nameLength+2:], q.Class)
	return bytes
}

// DNS names are encoded as a sequence of labels,
// where each label consists of a length octet
// followed by that number of octets, and terminated
// e.g. www.google.com -> 3www6google3com
func encodeDNSName(domain string) []byte {
	buffer := new(bytes.Buffer)
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		buffer.WriteByte(byte(len(label)))
		buffer.WriteString(label)
	}
	buffer.WriteByte(0)
	return buffer.Bytes()
}

func buildQuery(domain string, recursionDesired bool, recordType RecordType) []byte {
	id := rand.Intn(65535)

	header := DNSHeader{
		ID:      uint16(id),
		Flags:   0,
		QDCount: 1,
	}

	// Set RD flag to 1 if recursionDesired is true
	if recursionDesired {
		header.setFlags(0, 0, 0, 0, 1, 0, 0, 0)
	}

	question := DNSQuestion{
		Name:  encodeDNSName(domain),
		Type:  uint16(recordType),
		Class: uint16(IN),
	}

	buffer := new(bytes.Buffer)
	buffer.Write(header.toBytes())
	buffer.Write(question.toBytes())
	return buffer.Bytes()
}

// SendQuery sends a DNS query to Google's public DNS server
// and returns the response as a byte slice (or an error)
func SendQuery(domain string, nameserver string, recordType RecordType) ([]byte, error) {
	conn, err := net.Dial("udp", nameserver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	query := buildQuery(domain, false, recordType)
	_, err = conn.Write(query)
	if err != nil {
		return nil, err
	}

	resp := make([]byte, 1024)
	_, err = conn.Read(resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
