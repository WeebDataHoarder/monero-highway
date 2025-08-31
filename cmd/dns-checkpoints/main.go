package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func main() {
	apiBind := flag.String("api-bind", "127.0.0.1:19080", "address to bind the HTTP API")
	bind := flag.String("bind", "0.0.0.0:15353", "address to bind DNS server to, UDP and TCP")
	ttl := flag.Duration("ttl", time.Minute*5, "TTL to set on responses, with seconds granularity")
	domainZoneStr := flag.String("zone", "a.example.com.", "domain zone to reply for")
	ns1Str := flag.String("ns1", "ns1.example.com.", "main nameserver for the zone")
	keyFile := flag.String("key", os.Getenv("MONERO_HIGHWAY_KEY"), "DER/PEM encoded private key. Alternatively, use MONERO_HIGHWAY_KEY environment variable")

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

	var privateKey crypto.Signer
	if *keyFile == "" {
		slog.Warn("no private key file provided via -key or MONERO_HIGHWAY_KEY. Generating random secp256r1 key.")
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			slog.Error("Failed to generate private key", "error", err)
			panic(err)
		}
		der, err := x509.MarshalECPrivateKey(pk)
		if err != nil {
			slog.Error("Failed to marshal private key", "error", err)
			panic(err)
		}
		pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
		buf := pem.EncodeToMemory(pb)
		if buf == nil {
			slog.Error("Failed to encode private key")
			panic("Failed to encode private key")
		}

		slog.Warn("Generated private key", "type", "secp256r1", "pem", buf)
		_, _ = fmt.Fprintf(os.Stderr, "\n%s\n", buf)
		privateKey = pk
	} else {
		keyData, err := os.ReadFile(*keyFile)
		if err != nil {
			slog.Error("Failed to read private key file", "error", err)
			panic(err)
		}

		// handle pem
		if decodedBlock, _ := pem.Decode(keyData); decodedBlock != nil {
			keyData = decodedBlock.Bytes
		}

		key, err := x509.ParseECPrivateKey(keyData)
		if err != nil {
			key, err2 := x509.ParsePKCS1PrivateKey(keyData)
			if err2 != nil {
				slog.Error("Failed to parse private key", "error", err, "error2", err2)
				key, err3 := x509.ParsePKCS8PrivateKey(keyData)
				if err3 != nil {
					slog.Error("Failed to parse private key", "error", err, "error2", err2, "error3", err3)
					panic(err3)
				} else if signer, ok := key.(crypto.Signer); ok {
					privateKey = signer
				} else {
					panic("Private key does not implement crypto.Signer")
				}
			} else {
				privateKey = key
			}
		} else {
			privateKey = key
		}
		slog.Info("Loaded private key from file")
	}

	const soaTTL = time.Hour * 24 * 7
	signer, err := NewSigner(privateKey, domainZone, ns1, "", soaTTL, time.Minute)
	if err != nil {
		slog.Error("Failed to create signer", "error", err)
		panic(err)
	}

	slog.Info(fmt.Sprintf("DNSKEY pubkey %s", signer.DNSKEY().PublicKey), "record", strings.ReplaceAll(signer.DNSKEY().String(), "\t", " "))
	slog.Info(fmt.Sprintf("DS digest %s", signer.DS().Digest), "record", strings.ReplaceAll(signer.DS().String(), "\t", " "))

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
	signer.Add(signer.DNSKEY())
	signer.Add(signer.SOA(time.Now()))

	wg.Add(1)
	go func() {
		defer wg.Done()
		// refresh SOA
		for range time.Tick(soaTTL / 4) {
			signer.Add(signer.SOA(time.Now()))
		}
	}()

	// await for signatures
	for {
		if txt := signer.Get(dns.TypeSOA); txt != nil {
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

	if *apiBind != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()

			slog.Info("Starting HTTP server", "bind", *apiBind)

			if err := http.ListenAndServe(*apiBind, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
					return
				}
				values := r.URL.Query()

				var txt []dns.RR

				for _, entry := range values["txt"] {
					if len(entry) == 0 {
						continue
					}
					txt = append(txt, &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   domainZone,
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    recordTTL,
						},
						Txt: []string{entry},
					})
				}

				if len(txt) > 0 {
					signer.Add(txt...)
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusBadRequest)
				}
			})); err != nil {
				slog.Error("Failed to start HTTP server", "bind", *apiBind, "error", err)
			}
		}()
	}

	wg.Wait()
	slog.Error("Exiting, no active servers")
}
