package dns

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"bifrost/internal/session"
)

type Server struct {
	Addr          string
	Domain        string
	NSName        string
	SOAMailbox    string
	SOASerial     uint32
	Manager       *session.Manager
	Logger        *log.Logger
	TraceRequests bool

	conn *net.UDPConn
	wg   sync.WaitGroup
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		_ = conn.Close()
	}()
	buf := make([]byte, 4096)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				s.wg.Wait()
				return nil
			default:
				return err
			}
		}
		req := append([]byte(nil), buf[:n]...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			start := time.Now()
			resp := s.HandleDNSMessage(req)
			respBytes := 0
			if resp != nil {
				respBytes = len(resp)
			}
			if s.TraceRequests && s.Logger != nil {
				s.Logger.Printf("trace request transport=dns-udp remote=%s request_bytes=%d response_bytes=%d duration=%s", client, len(req), respBytes, time.Since(start))
			}
			if resp != nil {
				_, _ = conn.WriteToUDP(resp, client)
			}
		}()
	}
}

func (s *Server) HandleDNSMessage(req []byte) []byte {
	q, err := ParseQuery(req)
	if err != nil {
		resp, _ := BuildTXTResponse(req, nil, 1)
		return resp
	}
	if q.QClass != ClassIN {
		return s.response(req, nil, s.soaAuthority(), 0)
	}
	if sameName(q.QName, s.domain()) {
		switch q.QType {
		case TypeNS:
			return s.response(req, []ResourceRecord{s.nsRecord()}, nil, 0)
		case TypeSOA:
			return s.response(req, []ResourceRecord{s.soaRecord()}, nil, 0)
		case TypeTXT:
			return s.response(req, nil, s.soaAuthority(), 0)
		default:
			return s.response(req, nil, s.soaAuthority(), 0)
		}
	}
	if !inZone(q.QName, s.domain()) {
		return s.response(req, nil, nil, 5)
	}
	if q.QType != TypeTXT {
		return s.response(req, nil, s.soaAuthority(), 0)
	}
	payload, err := QNameToPayload(q.QName, s.Domain)
	if err != nil {
		return s.response(req, nil, s.soaAuthority(), 3)
	}
	out, err := s.Manager.HandlePacket(payload)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Printf("handle packet: %v", err)
		}
		resp, _ := BuildTXTResponse(req, nil, 5)
		return resp
	}
	resp, err := BuildTXTResponse(req, out, 0)
	if err != nil {
		return nil
	}
	return resp
}

func (s *Server) response(req []byte, answers, authorities []ResourceRecord, rcode uint8) []byte {
	resp, err := BuildResponse(req, answers, authorities, rcode)
	if err != nil {
		return nil
	}
	return resp
}

func (s *Server) nsRecord() ResourceRecord {
	rr, err := BuildNSRecord(s.domain(), s.nsName())
	if err != nil {
		return ResourceRecord{}
	}
	return rr
}

func (s *Server) soaRecord() ResourceRecord {
	serial := s.SOASerial
	if serial == 0 {
		serial = 1
	}
	rr, err := BuildSOARecord(s.domain(), s.nsName(), s.soaMailbox(), serial)
	if err != nil {
		return ResourceRecord{}
	}
	return rr
}

func (s *Server) soaAuthority() []ResourceRecord {
	return []ResourceRecord{s.soaRecord()}
}

func (s *Server) domain() string {
	return strings.Trim(strings.ToLower(s.Domain), ".")
}

func (s *Server) nsName() string {
	if s.NSName != "" {
		return strings.Trim(strings.ToLower(s.NSName), ".")
	}
	return "ns1." + parentDomain(s.domain())
}

func (s *Server) soaMailbox() string {
	if s.SOAMailbox != "" {
		return strings.Trim(strings.ToLower(s.SOAMailbox), ".")
	}
	return "hostmaster." + parentDomain(s.domain())
}

func sameName(a, b string) bool {
	return strings.Trim(strings.ToLower(a), ".") == strings.Trim(strings.ToLower(b), ".")
}

func inZone(name, zone string) bool {
	name = strings.Trim(strings.ToLower(name), ".")
	zone = strings.Trim(strings.ToLower(zone), ".")
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func parentDomain(domain string) string {
	parts := strings.Split(strings.Trim(domain, "."), ".")
	if len(parts) <= 2 {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[1:], ".")
}
