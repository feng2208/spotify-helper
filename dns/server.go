package dns

import (
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// DNSOverrideFunc is a function that returns the IP override for a host
// Takes host and clientIP as parameters for CIDR-based selection
type DNSOverrideFunc func(host string, clientIP string) string

// Server represents a DNS server
type Server struct {
	listenAddr  string
	resolver    *Resolver
	getOverride DNSOverrideFunc
}

// NewServer creates a new DNS server
func NewServer(listenAddr string, resolver *Resolver, getOverride DNSOverrideFunc) *Server {
	return &Server{
		listenAddr:  listenAddr,
		resolver:    resolver,
		getOverride: getOverride,
	}
}

// Start starts the UDP DNS server
func (s *Server) Start() error {
	// Start UDP server
	go func() {
		udpServer := &dns.Server{
			Addr:    s.listenAddr,
			Net:     "udp",
			Handler: dns.HandlerFunc(s.handleDNS),
		}
		log.Printf("DNS Server (UDP) listening on %s", s.listenAddr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Printf("DNS UDP server error: %v", err)
		}
	}()

	return nil
}

// handleDNS handles incoming DNS queries
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Get client IP from connection
	clientIP := ""
	if addr := w.RemoteAddr(); addr != nil {
		clientIP = addr.String()
	}

	// DNS requests typically contain only one question
	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	log.Printf("[DNS] Query: %s %s from %s", dns.TypeToString[q.Qtype], q.Name, clientIP)

	// Only handle A and AAAA queries
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		// Forward other query types to upstream
		s.forwardQuery(w, r)
		return
	}

	// Remove trailing dot from name
	name := strings.TrimSuffix(q.Name, ".")

	// Check for override, passing client IP for CIDR matching
	if ip := s.getOverride(name, clientIP); ip != "" {
		log.Printf("[DNS] Override: %s -> %s", name, ip)

		switch q.Qtype {
		case dns.TypeA:
			// Check if the IP is IPv4
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil && parsedIP.To4() != nil {
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    20,
					},
					A: parsedIP.To4(),
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeAAAA:
			// Check if the IP is IPv6
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil && parsedIP.To4() == nil {
				rr := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    20,
					},
					AAAA: parsedIP,
				}
				m.Answer = append(m.Answer, rr)
			}
			// If it's an IPv4 address but AAAA was requested, return empty response
		}

		w.WriteMsg(m)
		return
	}

	// No override, forward to upstream
	s.forwardQuery(w, r)
}

// forwardQuery forwards the DNS query to the upstream resolver
func (s *Server) forwardQuery(w dns.ResponseWriter, r *dns.Msg) {
	// Pack the original request
	data, err := r.Pack()
	if err != nil {
		log.Printf("[DNS] Failed to pack query: %v", err)
		return
	}

	// Forward based on resolver type
	var resp *dns.Msg
	if s.resolver.isDoH {
		resp, err = s.forwardDoH(data)
	} else {
		resp, err = s.forwardUDP(r)
	}

	if err != nil {
		log.Printf("[DNS] Forward failed: %v", err)
		// Return SERVFAIL
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	resp.Id = r.Id
	w.WriteMsg(resp)
}

// forwardUDP forwards query using traditional DNS
func (s *Server) forwardUDP(r *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp"}
	resp, _, err := c.Exchange(r, s.resolver.server)
	return resp, err
}

// forwardDoH forwards query using DNS-over-HTTPS
func (s *Server) forwardDoH(data []byte) (*dns.Msg, error) {
	// Use the resolver's DoH functionality
	resp, err := s.resolver.doDoHQuery(data)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
