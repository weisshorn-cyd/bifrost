package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHandleDNSMessageAnswersNSAtZoneApex(t *testing.T) {
	s := &Server{Domain: "cdn.c12y.ch"}
	resp := s.HandleDNSMessage(testQuery(t, 1, "cdn.c12y.ch", TypeNS))
	h := parseHeader(t, resp)
	if h.rcode != 0 || h.answers != 1 || h.authorities != 0 {
		t.Fatalf("rcode=%d answers=%d authorities=%d", h.rcode, h.answers, h.authorities)
	}
	rr := firstAnswer(t, resp)
	if rr.typ != TypeNS || rr.name != "cdn.c12y.ch" {
		t.Fatalf("answer = %s type %d, want cdn.c12y.ch NS", rr.name, rr.typ)
	}
	ns, _, err := readName(rr.rdata, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ns != "ns1.c12y.ch" {
		t.Fatalf("ns = %q, want ns1.c12y.ch", ns)
	}
}

func TestHandleDNSMessageAnswersSOAAtZoneApex(t *testing.T) {
	s := &Server{Domain: "cdn.c12y.ch", NSName: "bifrost-ns.c12y.ch", SOAMailbox: "admin.c12y.ch", SOASerial: 42}
	resp := s.HandleDNSMessage(testQuery(t, 1, "cdn.c12y.ch", TypeSOA))
	h := parseHeader(t, resp)
	if h.rcode != 0 || h.answers != 1 || h.authorities != 0 {
		t.Fatalf("rcode=%d answers=%d authorities=%d", h.rcode, h.answers, h.authorities)
	}
	rr := firstAnswer(t, resp)
	if rr.typ != TypeSOA || rr.name != "cdn.c12y.ch" {
		t.Fatalf("answer = %s type %d, want cdn.c12y.ch SOA", rr.name, rr.typ)
	}
	mname, off, err := readName(rr.rdata, 0)
	if err != nil {
		t.Fatal(err)
	}
	rname, off, err := readName(rr.rdata, off)
	if err != nil {
		t.Fatal(err)
	}
	if mname != "bifrost-ns.c12y.ch" || rname != "admin.c12y.ch" {
		t.Fatalf("soa names = %q %q", mname, rname)
	}
	if got := binary.BigEndian.Uint32(rr.rdata[off : off+4]); got != 42 {
		t.Fatalf("serial = %d, want 42", got)
	}
}

func TestHandleDNSMessageReturnsNodataWithSOAForUnsupportedInZoneType(t *testing.T) {
	s := &Server{Domain: "cdn.c12y.ch"}
	resp := s.HandleDNSMessage(testQuery(t, 1, "www.cdn.c12y.ch", TypeA))
	h := parseHeader(t, resp)
	if h.rcode != 0 || h.answers != 0 || h.authorities != 1 {
		t.Fatalf("rcode=%d answers=%d authorities=%d", h.rcode, h.answers, h.authorities)
	}
}

func TestHandleDNSMessageRefusesOutOfZone(t *testing.T) {
	s := &Server{Domain: "cdn.c12y.ch"}
	resp := s.HandleDNSMessage(testQuery(t, 1, "example.com", TypeNS))
	h := parseHeader(t, resp)
	if h.rcode != 5 || h.answers != 0 {
		t.Fatalf("rcode=%d answers=%d, want REFUSED with no answers", h.rcode, h.answers)
	}
}

type dnsHeader struct {
	rcode       uint8
	questions   uint16
	answers     uint16
	authorities uint16
}

type parsedRR struct {
	name  string
	typ   uint16
	rdata []byte
}

func testQuery(t *testing.T, id uint16, name string, typ uint16) []byte {
	t.Helper()
	var b bytes.Buffer
	writeHeader(&b, id, 0x0100, 1, 0, 0, 0)
	if err := writeName(&b, name); err != nil {
		t.Fatal(err)
	}
	_ = binary.Write(&b, binary.BigEndian, typ)
	_ = binary.Write(&b, binary.BigEndian, ClassIN)
	return b.Bytes()
}

func parseHeader(t *testing.T, msg []byte) dnsHeader {
	t.Helper()
	if len(msg) < 12 {
		t.Fatalf("short response: %d bytes", len(msg))
	}
	return dnsHeader{
		rcode:       uint8(binary.BigEndian.Uint16(msg[2:4]) & 0xf),
		questions:   binary.BigEndian.Uint16(msg[4:6]),
		answers:     binary.BigEndian.Uint16(msg[6:8]),
		authorities: binary.BigEndian.Uint16(msg[8:10]),
	}
}

func firstAnswer(t *testing.T, msg []byte) parsedRR {
	t.Helper()
	off := 12
	h := parseHeader(t, msg)
	for i := 0; i < int(h.questions); i++ {
		var err error
		_, off, err = readName(msg, off)
		if err != nil {
			t.Fatal(err)
		}
		off += 4
	}
	name, off, err := readName(msg, off)
	if err != nil {
		t.Fatal(err)
	}
	if off+10 > len(msg) {
		t.Fatalf("short rr header")
	}
	typ := binary.BigEndian.Uint16(msg[off : off+2])
	rdLen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	off += 10
	if off+rdLen > len(msg) {
		t.Fatalf("short rr rdata")
	}
	return parsedRR{name: name, typ: typ, rdata: msg[off : off+rdLen]}
}
