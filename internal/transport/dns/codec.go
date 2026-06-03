package dns

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	TypeA    uint16 = 1
	TypeNS   uint16 = 2
	TypeSOA  uint16 = 6
	TypeTXT  uint16 = 16
	ClassIN  uint16 = 1
	ttl             = 60
	maxLabel        = 63
)

var b32 = base32.HexEncoding.WithPadding(base32.NoPadding)

type Message struct {
	ID       uint16
	QName    string
	QType    uint16
	QClass   uint16
	Response bool
	Payload  []byte
	RCode    uint8
}

type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

func PayloadToQName(payload []byte, domain string) (string, error) {
	enc := strings.ToLower(b32.EncodeToString(payload))
	labels := []string{"v1"}
	for len(enc) > 0 {
		n := maxLabel
		if len(enc) < n {
			n = len(enc)
		}
		labels = append(labels, enc[:n])
		enc = enc[n:]
	}
	if domain != "" {
		labels = append(labels, strings.Trim(domain, "."))
	}
	name := strings.Join(labels, ".")
	if len(name)+1 > 255 {
		return "", fmt.Errorf("encoded qname exceeds 255 bytes")
	}
	return name, nil
}

func QNameToPayload(qname, domain string) ([]byte, error) {
	qname = strings.Trim(strings.ToLower(qname), ".")
	domain = strings.Trim(strings.ToLower(domain), ".")
	if domain != "" {
		suffix := "." + domain
		if qname == domain || !strings.HasSuffix(qname, suffix) {
			return nil, fmt.Errorf("qname %q outside domain %q", qname, domain)
		}
		qname = strings.TrimSuffix(qname, suffix)
	}
	parts := strings.Split(qname, ".")
	if len(parts) < 2 || parts[0] != "v1" {
		return nil, errors.New("unsupported qname prefix")
	}
	return b32.DecodeString(strings.ToUpper(strings.Join(parts[1:], "")))
}

func BuildQuery(id uint16, payload []byte, domain string) ([]byte, error) {
	qname, err := PayloadToQName(payload, domain)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	writeHeader(&b, id, 0x0100, 1, 0, 0, 0)
	if err := writeName(&b, qname); err != nil {
		return nil, err
	}
	_ = binary.Write(&b, binary.BigEndian, TypeTXT)
	_ = binary.Write(&b, binary.BigEndian, ClassIN)
	return b.Bytes(), nil
}

func ParseQuery(msg []byte) (Message, error) {
	if len(msg) < 12 {
		return Message{}, errors.New("short dns query")
	}
	qd := binary.BigEndian.Uint16(msg[4:6])
	if qd != 1 {
		return Message{}, errors.New("expected exactly one question")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	name, off, err := readName(msg, 12)
	if err != nil {
		return Message{}, err
	}
	if off+4 > len(msg) {
		return Message{}, errors.New("short dns question")
	}
	return Message{ID: id, QName: name, QType: binary.BigEndian.Uint16(msg[off : off+2]), QClass: binary.BigEndian.Uint16(msg[off+2 : off+4])}, nil
}

func BuildTXTResponse(query []byte, payload []byte, rcode uint8) ([]byte, error) {
	q, err := ParseQuery(query)
	if err != nil {
		return nil, err
	}
	var answers []ResourceRecord
	if rcode == 0 {
		txt := splitTXT(payload)
		var rdata bytes.Buffer
		for _, s := range txt {
			rdata.WriteByte(byte(len(s)))
			rdata.Write(s)
		}
		answers = []ResourceRecord{{Name: q.QName, Type: TypeTXT, Class: ClassIN, TTL: ttl, RData: rdata.Bytes()}}
	}
	return BuildResponse(query, answers, nil, rcode)
}

func BuildResponse(query []byte, answers, authorities []ResourceRecord, rcode uint8) ([]byte, error) {
	q, err := ParseQuery(query)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	flags := uint16(0x8000 | 0x0400 | uint16(rcode&0xf))
	writeHeader(&b, q.ID, flags, 1, uint16(len(answers)), uint16(len(authorities)), 0)
	if err := writeQuestion(&b, q); err != nil {
		return nil, err
	}
	for _, rr := range answers {
		if err := writeResourceRecord(&b, rr, q.QName); err != nil {
			return nil, err
		}
	}
	for _, rr := range authorities {
		if err := writeResourceRecord(&b, rr, q.QName); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func BuildNSRecord(name, nsName string) (ResourceRecord, error) {
	rdata, err := nameRData(nsName)
	if err != nil {
		return ResourceRecord{}, err
	}
	return ResourceRecord{Name: name, Type: TypeNS, Class: ClassIN, TTL: ttl, RData: rdata}, nil
}

func BuildSOARecord(name, nsName, mailbox string, serial uint32) (ResourceRecord, error) {
	var rdata bytes.Buffer
	if err := writeName(&rdata, nsName); err != nil {
		return ResourceRecord{}, err
	}
	if err := writeName(&rdata, mailbox); err != nil {
		return ResourceRecord{}, err
	}
	for _, v := range []uint32{serial, 3600, 600, 86400, ttl} {
		_ = binary.Write(&rdata, binary.BigEndian, v)
	}
	return ResourceRecord{Name: name, Type: TypeSOA, Class: ClassIN, TTL: ttl, RData: rdata.Bytes()}, nil
}

func nameRData(name string) ([]byte, error) {
	var b bytes.Buffer
	if err := writeName(&b, name); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func ParseTXTResponse(msg []byte) (Message, error) {
	if len(msg) < 12 {
		return Message{}, errors.New("short dns response")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode := uint8(flags & 0xf)
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	var qname string
	var err error
	for i := 0; i < qd; i++ {
		qname, off, err = readName(msg, off)
		if err != nil {
			return Message{}, err
		}
		off += 4
		if off > len(msg) {
			return Message{}, errors.New("short dns response question")
		}
	}
	if rcode != 0 {
		return Message{ID: id, QName: qname, Response: true, RCode: rcode}, nil
	}
	for i := 0; i < an; i++ {
		_, next, err := readName(msg, off)
		if err != nil {
			return Message{}, err
		}
		off = next
		if off+10 > len(msg) {
			return Message{}, errors.New("short dns answer")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdLen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdLen > len(msg) {
			return Message{}, errors.New("short dns rdata")
		}
		if typ == TypeTXT {
			var payload []byte
			end := off + rdLen
			for off < end {
				n := int(msg[off])
				off++
				if off+n > end {
					return Message{}, errors.New("invalid txt chunk")
				}
				payload = append(payload, msg[off:off+n]...)
				off += n
			}
			return Message{ID: id, QName: qname, Response: true, Payload: payload}, nil
		}
		off += rdLen
	}
	return Message{}, errors.New("no txt answer")
}

func writeHeader(b *bytes.Buffer, id, flags, qd, an, ns, ar uint16) {
	_ = binary.Write(b, binary.BigEndian, id)
	_ = binary.Write(b, binary.BigEndian, flags)
	_ = binary.Write(b, binary.BigEndian, qd)
	_ = binary.Write(b, binary.BigEndian, an)
	_ = binary.Write(b, binary.BigEndian, ns)
	_ = binary.Write(b, binary.BigEndian, ar)
}

func writeQuestion(b *bytes.Buffer, q Message) error {
	if err := writeName(b, q.QName); err != nil {
		return err
	}
	_ = binary.Write(b, binary.BigEndian, q.QType)
	qclass := q.QClass
	if qclass == 0 {
		qclass = ClassIN
	}
	_ = binary.Write(b, binary.BigEndian, qclass)
	return nil
}

func writeResourceRecord(b *bytes.Buffer, rr ResourceRecord, questionName string) error {
	if sameDNSName(rr.Name, questionName) {
		b.WriteByte(0xc0)
		b.WriteByte(0x0c)
	} else {
		if err := writeName(b, rr.Name); err != nil {
			return err
		}
	}
	class := rr.Class
	if class == 0 {
		class = ClassIN
	}
	_ = binary.Write(b, binary.BigEndian, rr.Type)
	_ = binary.Write(b, binary.BigEndian, class)
	_ = binary.Write(b, binary.BigEndian, rr.TTL)
	_ = binary.Write(b, binary.BigEndian, uint16(len(rr.RData)))
	b.Write(rr.RData)
	return nil
}

func sameDNSName(a, b string) bool {
	return strings.Trim(strings.ToLower(a), ".") == strings.Trim(strings.ToLower(b), ".")
}

func writeName(b *bytes.Buffer, name string) error {
	for _, label := range strings.Split(strings.Trim(name, "."), ".") {
		if len(label) == 0 || len(label) > maxLabel {
			return fmt.Errorf("invalid dns label length %d", len(label))
		}
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	return nil
}

func readName(msg []byte, off int) (string, int, error) {
	labels := []string{}
	start := off
	jumped := false
	seen := 0
	for {
		if off >= len(msg) {
			return "", 0, errors.New("short dns name")
		}
		l := int(msg[off])
		if l&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return "", 0, errors.New("short dns pointer")
			}
			ptr := ((l & 0x3f) << 8) | int(msg[off+1])
			if ptr >= len(msg) {
				return "", 0, errors.New("invalid dns pointer")
			}
			if !jumped {
				start = off + 2
			}
			off = ptr
			jumped = true
			seen++
			if seen > 16 {
				return "", 0, errors.New("dns pointer loop")
			}
			continue
		}
		off++
		if l == 0 {
			break
		}
		if l > maxLabel || off+l > len(msg) {
			return "", 0, errors.New("invalid dns label")
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	if jumped {
		off = start
	}
	return strings.Join(labels, "."), off, nil
}

func splitTXT(payload []byte) [][]byte {
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	var out [][]byte
	for len(payload) > 0 {
		n := 255
		if len(payload) < n {
			n = len(payload)
		}
		out = append(out, payload[:n])
		payload = payload[n:]
	}
	return out
}
