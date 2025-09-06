package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
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
	keyType := flag.String("generate-key-type", "ed25519", "type of key to generate, allowed values (ed25519, secp256r1, secp384r1, rsa2048, rsa4096)")
	keyFile := flag.String("key", os.Getenv("MONERO_HIGHWAY_KEY"), "DER/PEM encoded private key. Alternatively, use MONERO_HIGHWAY_KEY environment variable")

	var axfrNotify utils.MultiStringFlag
	axfr := flag.Bool("axfr", false, "allow zone transfers via AXFR TCP transfers")
	flag.Var(&axfrNotify, "axfr-notify", "servers or addresses with defined port to NOTIFY for a desired AXFR transfer")

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
		slog.Warn("no private key file provided via -key or MONERO_HIGHWAY_KEY. Generating random key.")
		var der []byte
		switch *keyType {
		default:
			slog.Error("Unknown key type", "type", *keyType)
			panic("unknown key type")
		case "ed25519", "":
			*keyType = "ed25519"
			_, pk, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				slog.Error("Failed to generate private key", "error", err)
				panic(err)
			}
			opts.PrivateKey = pk
		case "secp256r1", "prime256v1", "secp384r1":
			var pk *ecdsa.PrivateKey
			var err error
			if *keyType == "secp256r1" || *keyType == "prime256v1" {
				pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			} else {
				pk, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			}
			if err != nil {
				slog.Error("Failed to generate private key", "error", err)
				panic(err)
			}
			opts.PrivateKey = pk
		case "rsa2048", "rsa4096":
			var pk *rsa.PrivateKey
			var err error
			if *keyType == "rsa2048" {
				pk, err = rsa.GenerateKey(rand.Reader, 2048)
			} else {
				pk, err = rsa.GenerateKey(rand.Reader, 4096)
			}
			if err != nil {
				slog.Error("Failed to generate private key", "error", err)
				panic(err)
			}
			opts.PrivateKey = pk
		}

		der, err := x509.MarshalPKCS8PrivateKey(opts.PrivateKey)
		if err != nil {
			slog.Error("Failed to marshal private key", "error", err)
			panic(err)
		}
		pb := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
		buf := pem.EncodeToMemory(pb)
		if buf == nil {
			slog.Error("Failed to encode private key")
			panic("Failed to encode private key")
		}

		slog.Warn("Generated private key", "type", *keyType, "pem", buf)
		_, _ = fmt.Fprintf(os.Stderr, "\n%s\n", buf)
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
	slog.Info("DS KSK", "record", strings.ReplaceAll(signer.DS().String(), "\t", " "))
	for i, ns := range signer.NS() {
		slog.Info(fmt.Sprintf("NS%d", i+1), "record", strings.ReplaceAll(ns.String(), "\t", " "))
	}

	const udpBufferSize = dns.DefaultMsgSize

	var wg sync.WaitGroup
	notifyChannel := make(chan struct{})

	sendNotify := func() {
		select {
		case notifyChannel <- struct{}{}:
		default:
		}
	}

	if len(axfrNotify) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			client := new(dns.Client)

			for range notifyChannel {
				var msg dns.Msg
				msg.SetNotify(signer.Zone())
				msg.SetEdns0(udpBufferSize, true)
				soa := signer.Get(dns.TypeSOA)
				if soa == nil {
					continue
				}
				msg.Answer = append(msg.Answer, soa.RR...)
				for _, q := range axfrNotify {
					func() {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()

						resp, _, err := client.ExchangeContext(ctx, &msg, q)
						if err != nil {
							slog.Error("Sent NOTIFY to server, received error", "server", q, "error", err)
							return
						}
						if resp.Rcode != dns.RcodeSuccess {
							slog.Debug("Sent NOTIFY to server, received code", "server", q, "code", resp.Rcode)
						} else {
							slog.Debug("Sent NOTIFY to server success", "server", q, "code", resp.Rcode)
						}
					}()

				}
			}

		}()
	}

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
		Handler: RequestHandler(signer, false, *axfr, udpBufferSize),
	}

	dnsServerUDP := dns.Server{
		Addr:    *bind,
		Net:     "udp",
		Handler: RequestHandler(signer, true, false, udpBufferSize),
		UDPSize: udpBufferSize,
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
					go func() {
						time.Sleep(time.Second * 5)
						sendNotify()
						storeState(now)
					}()
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

	sendNotify()

	wg.Wait()
	slog.Error("Exiting, no active servers")
}
