// Package dnsweekend https://implement-dns.wizardzines.com/
package dnsweekend

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// DNSRecord (variable length)
type DNSRecord struct {
	Name  []byte // Name
	Type  uint16 // Type (A, AAAA, MX, NS, etc.)
	Class uint16 // Class (IN, CH, HS, etc.)
	TTL   uint32 // TTL
	data  []byte // Raw Data
}

// DNSPacket is a DNS packet
// (header + question + answer + authority + additional)
type DNSPacket struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSRecord
	Authorities []DNSRecord
	Additionals []DNSRecord
}

func parseDNSHeader(header *bytes.Reader) DNSHeader {
	idBytes := make([]byte, 2)
	flagsBytes := make([]byte, 2)
	qdCountBytes := make([]byte, 2)
	anCountBytes := make([]byte, 2)
	nsCountBytes := make([]byte, 2)
	arCountBytes := make([]byte, 2)
	header.Read(idBytes)
	header.Read(flagsBytes)
	header.Read(qdCountBytes)
	header.Read(anCountBytes)
	header.Read(nsCountBytes)
	header.Read(arCountBytes)

	return DNSHeader{
		ID:      binary.BigEndian.Uint16(idBytes),
		Flags:   binary.BigEndian.Uint16(flagsBytes),
		QDCount: binary.BigEndian.Uint16(qdCountBytes),
		ANCount: binary.BigEndian.Uint16(anCountBytes),
		NSCount: binary.BigEndian.Uint16(nsCountBytes),
		ARCount: binary.BigEndian.Uint16(arCountBytes),
	}
}

func parseDNSQuestion(question *bytes.Reader) DNSQuestion {
	name, err := decodeDNSName(question)
	if err != nil {
		panic(err)
	}

	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	question.Read(typeBytes)
	question.Read(classBytes)
	return DNSQuestion{
		Name:  []byte(name),
		Type:  binary.BigEndian.Uint16(typeBytes),
		Class: binary.BigEndian.Uint16(classBytes),
	}
}

func decodeDNSNameSimple(name []byte) (string, error) {
	var labels []string
	size, i := 0, 0
	for {
		// Checks if name is valid
		if len(name) <= 0 {
			return "", fmt.Errorf("Invalid name")
		}

		// Checks if we've reached the end of the name
		if name[i] == 0 {
			break
		}

		// Gets the size of the label and checks if it's valid
		if size == 0 {
			size = int(name[i])
			i++
			continue
		}
		if size > len(name) {
			return "", fmt.Errorf("Invalid name")
		}

		// Appends the label to the list of labels
		// and moves on to the next label
		// (i.e. the next byte after the label)
		label := string(name[i : i+size])
		labels = append(labels, label)
		name = name[i+size:]
		size, i = 0, 0
	}

	if len(labels) == 0 {
		return "", nil
	}
	domain := strings.Join(labels, ".")
	return domain, nil
}

func decodeDNSName(name *bytes.Reader) (string, error) {
	var labels []string

	// Keeps track of the current position
	// in the Reader so we can go back to it
	// if we encounter a pointer
	var readerIndex int64
	for {
		size, err := name.ReadByte()
		if err == io.EOF {
			return "", fmt.Errorf("Invalid name")
		}

		// Checks if we've reached the end of the name
		// and goes back to the position where we first
		// encountered a pointer
		if size == 0 {
			if readerIndex != 0 {
				_, _ = name.Seek(readerIndex, io.SeekStart)
			}
			break
		}

		// Checks if the size is compressed
		// (the first two bits are 11)
		if (size & 0b11000000) == 0b11000000 {
			// Combines the next byte with the last
			// 6 bits of the size to get the offset of the pointer
			offset := size & 0b00111111
			nextByte, _ := name.ReadByte()
			pointer := binary.BigEndian.Uint16([]byte{offset, nextByte})

			// Saves the current position in the Reader
			// only if we haven't already saved it before
			// (i.e. if we haven't encountered a pointer before)
			if readerIndex == 0 {
				readerIndex, _ = name.Seek(0, io.SeekCurrent)
			}
			// Moves the Reader to the position indicated
			// by the pointer and gets the size of the label
			_, _ = name.Seek(int64(pointer), io.SeekStart)
			size, _ = name.ReadByte()
		}
		label := make([]byte, size)
		_, _ = name.Read(label)
		labels = append(labels, string(label))
	}

	domain := strings.Join(labels, ".")
	return domain, nil
}

func parseDNSRecord(record *bytes.Reader) DNSRecord {
	name, err := decodeDNSName(record)
	if err != nil {
		panic(err)
	}

	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	ttlBytes := make([]byte, 4)
	dataLengthBytes := make([]byte, 2)
	record.Read(typeBytes)
	record.Read(classBytes)
	record.Read(ttlBytes)
	record.Read(dataLengthBytes)

	recordType := binary.BigEndian.Uint16(typeBytes)
	recordClass := binary.BigEndian.Uint16(classBytes)
	recordTTL := binary.BigEndian.Uint32(ttlBytes)
	var recordData []byte

	switch recordType {
	case uint16(NS):
		dnsName, _ := decodeDNSName(record)
		recordData = []byte(dnsName)
	case uint16(A):
		dataLength := binary.BigEndian.Uint16(dataLengthBytes)
		dataBytes := make([]byte, dataLength)
		record.Read(dataBytes)
		recordData = dataBytes
	case uint16(AAAA):
		dataLength := binary.BigEndian.Uint16(dataLengthBytes)
		dataBytes := make([]byte, dataLength)
		record.Read(dataBytes)
		recordData = dataBytes
	default:
		dataLength := binary.BigEndian.Uint16(dataLengthBytes)
		dataBytes := make([]byte, dataLength)
		record.Read(dataBytes)
		recordData = dataBytes
	}

	return DNSRecord{
		Name:  []byte(name),
		Type:  recordType,
		Class: recordClass,
		TTL:   recordTTL,
		data:  recordData,
	}
}

func parseDNSPacket(packet *bytes.Reader) DNSPacket {
	header := parseDNSHeader(packet)

	dnsQuestions := []DNSQuestion{}
	questionLen := int(header.QDCount)
	for i := 0; i < questionLen; i++ {
		dnsQuestion := parseDNSQuestion(packet)
		dnsQuestions = append(dnsQuestions, dnsQuestion)
	}

	answers := []DNSRecord{}
	answersLen := int(header.ANCount)
	for i := 0; i < answersLen; i++ {
		answer := parseDNSRecord(packet)
		answers = append(answers, answer)
	}

	authorities := []DNSRecord{}
	authoritiesLen := int(header.NSCount)
	for i := 0; i < authoritiesLen; i++ {
		authority := parseDNSRecord(packet)
		authorities = append(authorities, authority)
	}

	additionals := []DNSRecord{}
	additionalsLen := int(header.ARCount)
	for i := 0; i < additionalsLen; i++ {
		additional := parseDNSRecord(packet)
		additionals = append(additionals, additional)
	}

	return DNSPacket{
		Header:      header,
		Questions:   dnsQuestions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}
}

func dataIPtoString(dataIP []byte) string {
	dataParts := make([]string, 0)
	for _, val := range dataIP {
		part := strconv.FormatInt(int64(val), 10)
		dataParts = append(dataParts, part)
	}
	return strings.Join(dataParts, ".")
}

// LookupDomain sends a DNS query to a DNS server
// and returns the IP address of the domain (or an error)
func LookupDomain(domain string) (string, error) {
	resp, err := SendQuery(domain, "8.8.8.8:53", A)
	if err != nil {
		return "", nil
	}
	respReader := bytes.NewReader(resp)
	dnsPacket := parseDNSPacket(respReader)

	data := dnsPacket.Answers[0].data
	return dataIPtoString(data), nil
}
