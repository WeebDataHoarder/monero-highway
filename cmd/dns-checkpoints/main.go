package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func main() {
	bind := flag.String("bind", "0.0.0.0:15353", "address to bind DNS server to, UDP and TCP")
	ttl := flag.Duration("ttl", time.Minute*5, "TTL to set on responses, with seconds granularity")
	domainZoneStr := flag.String("zone", "a.example.com.", "domain zone to reply for")
	ns1Str := flag.String("ns1", "ns1.example.com.", "main nameserver for the zone")

	flag.Parse()

	p := NewReplyPool()

	recordTTL := uint32(*ttl / time.Second)

	domainZone := *domainZoneStr
	if !strings.HasSuffix(domainZone, ".") {
		slog.Warn("-domain does not end with . suffix, adding", "domain", domainZone)
		domainZone += "."
	}
	ns1 := *ns1Str
	if !strings.HasSuffix(ns1, ".") {
		slog.Warn("-ns1 does not end with . suffix, adding", "ns1", ns1)
		ns1 += "."
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("Failed to generate private key", "error", err)
		panic(err)
	}

	const soaTTL = time.Hour * 24 * 7
	signer, err := NewSigner(privateKey, domainZone, ns1, "", soaTTL, time.Minute)
	if err != nil {
		slog.Error("Failed to create signer", "error", err)
		panic(err)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := signer.Process(time.Duration(recordTTL) * time.Second)
		if err != nil {
			slog.Error("Failed to process record", "error", err)
			panic(err)
		}
	}()

	signer.Add(signer.DS())
	signer.Add(signer.SOA(time.Now()))
	signer.Add(signer.DNSKEY())

	wg.Add(1)
	go func() {
		defer wg.Done()
		// refresh SOA
		for range time.Tick(soaTTL / 4) {
			signer.Add(signer.SOA(time.Now()))
		}
	}()

	signer.Add(
		&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   domainZone,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    recordTTL,
			},
			Txt: []string{
				"a",
			},
		},
		&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   domainZone,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    recordTTL,
			},
			Txt: []string{
				"b",
			},
		},
	)

	for {
		if txt := signer.Get(dns.TypeTXT); txt != nil {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 || r.Opcode != dns.OpcodeQuery {
			return
		}

		msg := p.Get()
		defer p.Put(msg)

		for _, q := range r.Question {
			if q.Qclass == dns.ClassINET && q.Name == domainZone {
				answer := signer.Get(q.Qtype)
				if answer != nil {
					var isDNSSEC bool
					if dns0 := r.IsEdns0(); dns0 != nil {
						isDNSSEC = dns0.Do()
					}
					msg.Authoritative = true
					msg.Answer = append(msg.Answer, answer.RR...)
					if isDNSSEC {
						msg.Answer = append(msg.Answer, answer.Sig)
					}
					// disallow multiple queries to same match
					break
				}
			}
		}

		if len(msg.Answer) > 0 {
			// only set reply at the end
			msg.SetReply(r)
			_ = w.WriteMsg(msg)
		}
	})

	dnsServerTCP := &dns.Server{
		Addr:    *bind,
		Net:     "tcp",
		Handler: handler,
	}

	dnsServerUDP := dns.Server{
		Addr:    *bind,
		Net:     "udp",
		Handler: handler,
	}

	//TODO: drop privileges if given root / port 53

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("Starting DNS server on TCP", "bind", dnsServerTCP.Addr)
		if err := dnsServerTCP.ListenAndServe(); err != nil {
			if err != nil {
				slog.Error("Failed to start DNS server on TCP", "bind", dnsServerTCP.Addr, "error", err)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("Starting DNS server on UDP", "bind", dnsServerUDP.Addr)
		if err := dnsServerUDP.ListenAndServe(); err != nil {
			if err != nil {
				slog.Error("Failed to start DNS server on UDP", "bind", dnsServerUDP.Addr, "error", err)
			}
		}
	}()

	wg.Wait()
	slog.Error("Exiting, no active servers")
}
