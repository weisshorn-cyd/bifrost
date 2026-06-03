package policy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Policy struct {
	rules []rule
}

type rule struct {
	host string
	port string
	cidr *net.IPNet
}

func New(allowList string) (*Policy, error) {
	p := &Policy{}
	for _, item := range strings.Split(allowList, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		host, port, err := net.SplitHostPort(item)
		if err != nil {
			i := strings.LastIndex(item, ":")
			if i < 0 {
				return nil, fmt.Errorf("invalid allow rule %q", item)
			}
			host, port = item[:i], item[i+1:]
		}
		r := rule{host: strings.ToLower(strings.Trim(host, "[]")), port: port}
		if _, n, err := net.ParseCIDR(r.host); err == nil {
			r.cidr = n
		}
		if port != "*" {
			if _, err := strconv.Atoi(port); err != nil {
				return nil, fmt.Errorf("invalid port in allow rule %q", item)
			}
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func (p *Policy) Allow(dest string) bool {
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return false
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	for _, r := range p.rules {
		if r.port != "*" && r.port != port {
			continue
		}
		if r.host == "*" || r.host == host {
			return true
		}
		if r.cidr != nil {
			if ip := net.ParseIP(host); ip != nil && r.cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}
