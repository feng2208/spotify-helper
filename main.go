package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"spotify-helper/ca"
	"spotify-helper/config"
	"spotify-helper/dns"
	"spotify-helper/proxy"
)

func main() {
	// Parse command line arguments
	dnsUpstream := flag.String("dns-upstream", "8.8.8.8:53", "Upstream DNS server (use https:// prefix for DoH)")
	dnsListen := flag.String("dns", ":53", "DNS server listen address")
	listenAddr := flag.String("listen", ":443", "SNI Proxy listen address")
	httpListenAddr := flag.String("http", ":80", "HTTP listen address (e.g. :80) for redirect and transparent proxy")
	configPath := flag.String("config", "./config.yaml", "Configuration file path")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting SNI Proxy with MITM support")

	// Initialize CA manager
	caManager, err := ca.NewManager()
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}
	log.Println("CA certificate ready")

	// Load configuration
	var cfg *config.Manager
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		log.Printf("Warning: Config file not found at %s, using defaults", *configPath)
		cfg, _ = config.Load("")
	} else {
		cfg, err = config.Load(*configPath)
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}
	}
	log.Printf("Configuration loaded from %s", *configPath)

	// Initialize DNS resolver
	resolver := dns.NewResolver(*dnsUpstream)
	if isDoH := strings.HasPrefix(*dnsUpstream, "https://"); isDoH {
		log.Printf("Using DNS-over-HTTPS: %s", *dnsUpstream)
	} else {
		log.Printf("Using DNS server: %s", *dnsUpstream)
	}

	// Start DNS server
	dnsServer := dns.NewServer(*dnsListen, resolver, cfg.GetDNSOverride)
	if err := dnsServer.Start(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}

	// Create and start proxy server
	server := proxy.NewServer(*listenAddr, *httpListenAddr, caManager, cfg, resolver)

	fmt.Println()

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
