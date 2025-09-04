package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"git.gammaspectra.live/P2Pool/monero-highway/internal/utils"
	"github.com/miekg/dns"
)

func main() {
	opts := DefaultSignerOptions()

	apiBind := flag.String("api-bind", "127.0.0.1:19080", "address to bind the HTTP API")

	bind := flag.String("bind", "0.0.0.0:15353", "address to bind DNS server to, UDP and TCP")
	flag.DurationVar(&opts.RecordTTL, "ttl", opts.RecordTTL, "TTL to set on responses, with seconds granularity")
	flag.DurationVar(&opts.AuthorityTTL, "authority-ttl", opts.AuthorityTTL, "TTL to set on authority (SOA / NS / DS / DNSKEY / etc.) responses, with seconds granularity")

	flag.StringVar(&opts.Zone, "zone", opts.Zone, "domain zone to reply for")
	//TODO: multiple
	var nsValues utils.MultiStringFlag
	flag.Var(&nsValues, "ns", "nameservers for the zone. Can be specified multiple times")
	flag.StringVar(&opts.Mailbox, "mailbox", opts.Mailbox, "mailbox for the zone SOA record")
	keyFile := flag.String("key", os.Getenv("MONERO_HIGHWAY_KEY"), "DER/PEM encoded private key. Alternatively, use MONERO_HIGHWAY_KEY environment variable")
	axfr := flag.Bool("axfr", false, "allow zone transfers via AXFR TCP transfers")

	state := flag.String("state", "", "state file to preserve set TXT records to load on startup. A temporary file will be created next to it.")

	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	if !strings.HasSuffix(opts.Zone, ".") {
		slog.Warn("-domain does not end with . suffix, adding", "domain", opts.Zone)
		opts.Zone += "."
	}

	if !strings.HasSuffix(opts.Mailbox, ".") {
		slog.Warn("-mailbox does not end with . suffix, adding", "mailbox", opts.Mailbox)
		opts.Mailbox += "."
	}

	for i, ns := range nsValues {
		if !strings.HasSuffix(ns, ".") {
			slog.Warn("-ns does not end with . suffix, adding", "index", i, "ns", ns)
			ns += "."
		}
		opts.Nameservers = append(opts.Nameservers, ns)
	}

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
		opts.PrivateKey = pk
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
					opts.PrivateKey = signer
				} else {
					panic("Private key does not implement crypto.Signer")
				}
			} else {
				opts.PrivateKey = key
			}
		} else {
			opts.PrivateKey = key
		}
		slog.Info("Loaded private key from file")
	}

	signer, err := NewSigner(slog.Default(), opts)
	if err != nil {
		slog.Error("Failed to create signer", "error", err)
		panic(err)
	}

	slog.Info("DNSKEY ZSK", "record", strings.ReplaceAll(signer.DNSKEY()[0].String(), "\t", " "))
	slog.Info("DNSKEY KSK", "record", strings.ReplaceAll(signer.DNSKEY()[1].String(), "\t", " "))
	slog.Info("DS ZSK", "record", strings.ReplaceAll(signer.DS()[0].String(), "\t", " "))
	slog.Info("DS KSK", "record", strings.ReplaceAll(signer.DS()[1].String(), "\t", " "))
	for i, ns := range signer.NS() {
		slog.Info(fmt.Sprintf("NS%d", i+1), "record", strings.ReplaceAll(ns.String(), "\t", " "))
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := signer.Process(opts.RecordTTL / 2)
		if err != nil {
			slog.Error("Failed to process record", "error", err)
			panic(err)
		}
	}()

	signer.AddAuthorityRecords()
	signer.Add(&dns.A{
		Hdr: dns.RR_Header{
			Name:   signer.Zone(),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    TTL(opts.RecordTTL),
		},
		A: net.IP{0, 0, 0, 0},
	})

	var storeState = func(ts time.Time) {

	}

	if *state != "" {
		stateData, err := os.ReadFile(*state)
		if err != nil {
			slog.Warn("Failed to read state file", "error", err)
		} else {
			var data []string
			err = json.Unmarshal(stateData, &data)
			if err != nil {
				slog.Warn("Failed to unpack state file", "error", err)
			} else {
				var txt []dns.RR

				for _, entry := range data {
					if len(entry) == 0 {
						continue
					}
					txt = append(txt, &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   signer.Zone(),
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    TTL(opts.RecordTTL),
						},
						Txt: []string{entry},
					})
				}

				signer.Add(txt...)
				slog.Info("Loaded state file", "records", len(txt))
			}
		}
		var stateMutex sync.Mutex
		var lastTs time.Time
		storeState = func(ts time.Time) {
			stateMutex.Lock()
			defer stateMutex.Unlock()

			// check origin of call
			if lastTs.After(ts) {
				return
			}
			lastTs = ts

			records := signer.Get(dns.TypeTXT)
			if records == nil {
				return
			}
			var data []string
			for _, rr := range records.RR {
				if r, ok := rr.(*dns.TXT); ok {
					data = append(data, r.Txt[0])
				}
			}

			stateData, err := json.MarshalIndent(data, "", " ")
			if err != nil {
				slog.Warn("Failed to encode state", "error", err)
				return
			}

			var perm os.FileMode = 0644

			if stat, err := os.Stat(*state); err == nil {
				// preserve
				perm = stat.Mode().Perm()
			}
			err = os.WriteFile(*state+"_", stateData, perm)
			if err != nil {
				slog.Warn("Failed to write state file", "error", err)
				return
			}

			err = os.Rename(*state+"_", *state)
			if err != nil {
				slog.Warn("Failed to rename state file", "error", err)
				return
			}
			slog.Debug("Saved state file")
		}
	}

	// await for signatures
	for {
		if txt := signer.Get(dns.TypeNS); txt != nil {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}

	dnsServerTCP := &dns.Server{
		Addr:    *bind,
		Net:     "tcp",
		Handler: RequestHandler(signer, *axfr),
	}

	dnsServerUDP := dns.Server{
		Addr:    *bind,
		Net:     "udp",
		Handler: RequestHandler(signer, false),
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
				now := time.Now()
				defer func() {
					time.Sleep(time.Second * 5)
					storeState(now)
				}()

				values := r.URL.Query()

				var txt []dns.RR

				for _, entry := range values["txt"] {
					if len(entry) == 0 {
						continue
					}
					txt = append(txt, &dns.TXT{
						Hdr: dns.RR_Header{
							Name:   signer.Zone(),
							Rrtype: dns.TypeTXT,
							Class:  dns.ClassINET,
							Ttl:    TTL(opts.RecordTTL),
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
