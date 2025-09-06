package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type Signer struct {
	zoneLabels []string
	opts       SignerOptions

	kskDS dns.DS

	zsk dns.DNSKEY
	ksk dns.DNSKEY

	ns []*dns.NS

	records       [math.MaxUint16 + 1]*atomic.Pointer[SignedAnswer]
	recordChannel chan []dns.RR
	soa           atomic.Pointer[SignedAnswer]
	logger        *slog.Logger
}

type SignedAnswer struct {
	RR  []dns.RR
	Sig *dns.RRSIG
}

const DefaultRecordTTL = time.Minute * 5
const DefaultSignatureTTL = time.Hour
const DefaultRefreshTTL = time.Minute

// ClockSkewRange Time of expected clock skew on clients. See RFC 4035, Sec 5.3.1.
const ClockSkewRange = time.Second * 20

func TTL(d time.Duration) uint32 {
	// oh DNS, still using uint32 for time??? at least it's not int32
	return uint32(d / time.Second)
}

func DefaultSignerOptions() SignerOptions {
	return SignerOptions{
		RecordTTL:         DefaultRecordTTL,
		AuthorityTTL:      time.Hour * 24,
		RefreshTTL:        DefaultRefreshTTL,
		SignatureTTL:      DefaultSignatureTTL,
		SignatureBackdate: time.Hour * 24,
		Zone:              "checkpoints.example.com.",
		Mailbox:           "admin.example.com.",

		FingerprintAlgorithm: dns.SHA256,
	}
}

type SignerOptions struct {
	PrivateKey crypto.Signer

	RecordTTL    time.Duration
	AuthorityTTL time.Duration
	RefreshTTL   time.Duration

	SignatureTTL      time.Duration
	SignatureBackdate time.Duration

	FingerprintAlgorithm uint8

	Zone string

	Mailbox string

	Nameservers []string
}

func (so SignerOptions) PublicKey() (algorithm uint8, pub []byte, err error) {
	switch t := so.PrivateKey.(type) {
	case *rsa.PrivateKey:

		if pub, ok := t.Public().(*rsa.PublicKey); ok {
			buf := exponentToBuf(pub.E)
			buf = append(buf, pub.N.Bytes()...)
			return dns.RSASHA256, buf, nil
		}
	case ed25519.PrivateKey:
		algorithm = dns.ED25519
		if pub, ok := t.Public().(ed25519.PublicKey); ok {
			// as is bytes
			return dns.ED25519, pub, nil
		}
	case *ecdsa.PrivateKey:
		var intlen int
		switch t.Curve {
		case elliptic.P256():
			algorithm = dns.ECDSAP256SHA256
			intlen = 32
		case elliptic.P384():
			algorithm = dns.ECDSAP384SHA384
			intlen = 48
		default:
			return 0, nil, fmt.Errorf("unsupported elliptic curve: %s", t.Curve.Params().Name)
		}

		if pub, ok := t.Public().(*ecdsa.PublicKey); ok {
			return algorithm, curveToBuf(pub.X, pub.Y, intlen), nil
		}
	}

	return 0, nil, fmt.Errorf("unsupported private key type: %T", so.PrivateKey)
}

func NewSigner(logger *slog.Logger, opts SignerOptions) (*Signer, error) {
	if len(opts.Nameservers) == 0 {
		return nil, fmt.Errorf("not enough nameservers specified")
	}
	signer := &Signer{
		opts:          opts,
		logger:        logger,
		recordChannel: make(chan []dns.RR),
	}
	signer.zoneLabels = dns.SplitDomainName(opts.Zone)
	for i := range signer.records {
		signer.records[i] = new(atomic.Pointer[SignedAnswer])
	}

	algorithm, publicKey, err := signer.opts.PublicKey()
	if err != nil {
		return nil, err
	}

	signer.zsk = dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   signer.Zone(),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    TTL(signer.opts.AuthorityTTL),
		},
		// https://www.rfc-editor.org/rfc/rfc4034.html#section-2.1.1
		// https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1
		Flags:     dns.ZONE,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}

	signer.ksk = dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   signer.Zone(),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    TTL(signer.opts.AuthorityTTL),
		},
		// https://www.rfc-editor.org/rfc/rfc4034.html#section-2.1.1
		// https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1
		Flags:     dns.ZONE | dns.SEP,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}

	zskDS := signer.zsk.ToDS(signer.opts.FingerprintAlgorithm)
	if zskDS == nil {
		return nil, fmt.Errorf("failed to generate DS record")
	}

	kskDS := signer.ksk.ToDS(signer.opts.FingerprintAlgorithm)
	if kskDS == nil {
		return nil, fmt.Errorf("failed to generate DS record")
	}

	signer.kskDS = *kskDS

	for _, n := range signer.opts.Nameservers {
		signer.ns = append(signer.ns, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   signer.Zone(),
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    TTL(signer.opts.AuthorityTTL),
			},
			Ns: n,
		})
	}

	return signer, nil
}

// Process Processes regular signatures with a certain interval cadence. New record updates can be set via the incoming channel
func (s *Signer) Process(interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		// wait for ticker or a new incoming request
		case <-ticker.C:
			now := time.Now()
			// sign all existing records
			for i, srp := range s.records {
				if sr := srp.Load(); sr != nil {
					sig, err := s.sign(sr.RR, now)
					if err != nil {
						return err
					}
					s.records[i].Store(&SignedAnswer{
						RR:  sr.RR,
						Sig: sig,
					})
				}
			}
		case rr := <-s.recordChannel:
			now := time.Now()
			sig, err := s.sign(rr, now)
			if err != nil {
				return err
			}

			var updateNSEC = s.records[rr[0].Header().Rrtype].Load() == nil

			s.records[rr[0].Header().Rrtype].Store(&SignedAnswer{
				RR:  rr,
				Sig: sig,
			})

			// update NSEC with type existence
			if updateNSEC {
				if err = s.updateNSEC(now); err != nil {
					return err
				}
			}
		}

		now := time.Now()
		soa := s.SOA(now)
		sigSOA, err := s.sign([]dns.RR{soa}, now)
		if err != nil {
			return err
		}

		s.soa.Store(&SignedAnswer{
			RR:  []dns.RR{soa},
			Sig: sigSOA,
		})
	}
}

func (s *Signer) updateNSEC(now time.Time) error {
	var types []uint16
	for et, p := range s.records {
		if p.Load() == nil && uint16(et) != dns.TypeSOA && uint16(et) != dns.TypeRRSIG && uint16(et) != dns.TypeNSEC {
			continue
		}
		types = append(types, uint16(et))
	}

	rr := RR(&dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   s.Zone(),
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    TTL(s.opts.AuthorityTTL),
		},
		NextDomain: s.Zone(),
		TypeBitMap: types,
	})

	sig, err := s.sign(rr, now)
	if err != nil {
		return err
	}

	s.records[dns.TypeNSEC].Store(&SignedAnswer{
		RR:  rr,
		Sig: sig,
	})

	return nil
}

func (s *Signer) Transfer() (result []*SignedAnswer) {
	soa := s.soa.Load()
	if soa == nil {
		return
	}
	result = append(result, &SignedAnswer{
		RR: soa.RR,
	})
	for _, r := range s.records {
		if rr := r.Load(); rr != nil {
			result = append(result, rr)
		}
	}
	result = append(result, &SignedAnswer{
		RR: soa.RR,
	})
	return result
}

func (s *Signer) ZoneLabels() []string {
	return s.zoneLabels
}

func (s *Signer) Zone() string {
	return s.opts.Zone
}

func (s *Signer) Get(rtype uint16) *SignedAnswer {
	if rtype == dns.TypeSOA {
		return s.soa.Load()
	}
	return s.records[rtype].Load()
}

func (s *Signer) AddAuthorityRecords() {
	err := s.updateNSEC(time.Now())
	if err != nil {
		panic(err)
	}
	//s.Add(RR(s.DS())...)
	s.Add(RR(s.DNSKEY()...)...)

	// Add child DS/DNSKEY
	var cdsRR []*dns.CDS
	var dnskeyRR []*dns.CDNSKEY
	for _, dnsKey := range s.DNSKEY() {
		if dnsKey.Flags&dns.SEP > 0 {
			dnskeyRR = append(dnskeyRR, dnsKey.ToCDNSKEY())
			cdsRR = append(cdsRR, dnsKey.ToDS(s.opts.FingerprintAlgorithm).ToCDS())
		}
	}
	s.Add(RR(cdsRR...)...)
	s.Add(RR(dnskeyRR...)...)

	s.Add(RR(s.NS()...)...)
}

func (s *Signer) Add(rr ...dns.RR) {
	if len(rr) == 0 {
		return
	}

	r0 := rr[0]

	for _, r := range rr[1:] {
		if r.Header().Rrtype != r0.Header().Rrtype {
			panic("rtype mismatch")
		}
		if r.Header().Name != r0.Header().Name {
			panic("name mismatch")
		}
		if r.Header().Class != r0.Header().Class {
			panic("class mismatch")
		}
		if r.Header().Ttl != r0.Header().Ttl {
			panic("ttl mismatch")
		}
	}

	s.recordChannel <- slices.Clone(rr)

	for _, r := range rr {
		s.logger.Debug("adding record", "record", strings.ReplaceAll(r.String(), "\t", " "))
	}
}

func (s *Signer) DNSKEY() []*dns.DNSKEY {
	return []*dns.DNSKEY{
		&s.zsk,
		&s.ksk,
	}
}

func (s *Signer) DS() *dns.DS {
	return &s.kskDS
}

func RR[T dns.RR](s ...T) (r []dns.RR) {
	for _, e := range s {
		r = append(r, e)
	}
	return r
}

func (s *Signer) NS() []*dns.NS {
	return s.ns
}

func (s *Signer) SOA(now time.Time) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   s.Zone(),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    TTL(s.opts.AuthorityTTL),
		},
		Ns:     s.ns[0].Ns,
		Mbox:   s.opts.Mailbox,
		Serial: uint32(now.Unix()),

		Refresh: TTL(s.opts.RefreshTTL),
		Retry:   TTL(s.opts.RefreshTTL / 2),
		Expire:  TTL(min(s.opts.RefreshTTL*100, s.opts.AuthorityTTL)),
		Minttl:  TTL(s.opts.RefreshTTL / 2),
	}
}

func (s *Signer) sign(rr []dns.RR, now time.Time) (sig *dns.RRSIG, err error) {
	var key = &s.zsk
	switch rr[0].Header().Rrtype {
	case dns.TypeDNSKEY, dns.TypeCDNSKEY, dns.TypeCDS:
		key = &s.ksk
	}

	sigTTL := time.Duration(max(rr[0].Header().Ttl*2, TTL(s.opts.SignatureTTL))) * time.Second

	sig = &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   key.Hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  key.Hdr.Class,
			Ttl:    rr[0].Header().Ttl,
		},
		TypeCovered: rr[0].Header().Rrtype,
		Labels:      uint8(dns.CountLabel(rr[0].Header().Name)),
		OrigTtl:     rr[0].Header().Ttl,

		Expiration: uint32(now.Add(sigTTL + ClockSkewRange).Unix()),
		Inception:  uint32(now.Add(-s.opts.SignatureBackdate).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: key.Hdr.Name,
		Algorithm:  key.Algorithm,
	}

	if err = sig.Sign(s.opts.PrivateKey, rr); err != nil {
		return nil, err
	}
	return sig, nil
}

// Set the public key (the values E and N) for RSA
// RFC 3110: Section 2. RSA Public KEY Resource Records
func exponentToBuf(_E int) []byte {
	var buf []byte
	i := big.NewInt(int64(_E)).Bytes()
	if len(i) < 256 {
		buf = make([]byte, 1, 1+len(i))
		buf[0] = uint8(len(i))
	} else {
		buf = make([]byte, 3, 3+len(i))
		buf[0] = 0
		buf[1] = uint8(len(i) >> 8)
		buf[2] = uint8(len(i))
	}
	buf = append(buf, i...)
	return buf
}

// Set the public key for X and Y for Curve. The two
// values are just concatenated.
func curveToBuf(_X, _Y *big.Int, intlen int) []byte {
	buf := intToBytes(_X, intlen)
	buf = append(buf, intToBytes(_Y, intlen)...)
	return buf
}

// Helper function for packing and unpacking
func intToBytes(i *big.Int, length int) []byte {
	buf := i.Bytes()
	if len(buf) < length {
		b := make([]byte, length)
		copy(b[length-len(buf):], buf)
		return b
	}
	return buf
}
