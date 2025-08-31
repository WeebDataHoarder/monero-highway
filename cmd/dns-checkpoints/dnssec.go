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
	key crypto.Signer

	zone    string
	mailbox string

	zskDS dns.DS
	kskDS dns.DS

	zsk dns.DNSKEY
	ksk dns.DNSKEY

	ttl     uint32
	refresh uint32

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

func NewSigner(logger *slog.Logger, privateKey crypto.Signer, ttl, refresh time.Duration, zone, mailbox string, ns ...string) (*Signer, error) {
	if len(ns) == 0 {
		return nil, fmt.Errorf("not enough nameservers specified")
	}
	signer := &Signer{
		logger:        logger,
		zone:          zone,
		mailbox:       mailbox,
		key:           privateKey,
		ttl:           uint32(ttl / time.Second),
		refresh:       uint32(refresh / time.Second),
		recordChannel: make(chan []dns.RR),
	}
	for i := range signer.records {
		signer.records[i] = new(atomic.Pointer[SignedAnswer])
	}
	/*
			k.setPublicKeyRSA(priv.PublicKey.E, priv.PublicKey.N)
			return priv, nil
		case ECDSAP256SHA256, ECDSAP384SHA384:
			var c elliptic.Curve
			switch k.Algorithm {
			case ECDSAP256SHA256:
				c = elliptic.P256()
			case ECDSAP384SHA384:
				c = elliptic.P384()
			}
			priv, err := ecdsa.GenerateKey(c, rand.Reader)
			if err != nil {
				return nil, err
			}
			k.setPublicKeyECDSA(priv.PublicKey.X, priv.PublicKey.Y)
			return priv, nil
		case ED25519:
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			k.setPublicKeyED25519(pub)
	*/

	var algorithm uint8
	var publicKey []byte
	switch t := privateKey.(type) {
	case *rsa.PrivateKey:
		algorithm = dns.RSASHA256

		if pub, ok := t.Public().(*rsa.PublicKey); ok {
			buf := exponentToBuf(pub.E)
			buf = append(buf, pub.N.Bytes()...)
			publicKey = buf
		}
	case ed25519.PrivateKey:
		algorithm = dns.ED25519
		if pub, ok := t.Public().(ed25519.PublicKey); ok {
			// as is bytes
			publicKey = pub
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
			return nil, fmt.Errorf("unsupported elliptic curve: %s", t.Curve.Params().Name)
		}

		if pub, ok := t.Public().(*ecdsa.PublicKey); ok {
			publicKey = curveToBuf(pub.X, pub.Y, intlen)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	signer.zsk = dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   signer.zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    signer.ttl,
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
			Name:   signer.zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    signer.ttl,
		},
		// https://www.rfc-editor.org/rfc/rfc4034.html#section-2.1.1
		// https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.1
		Flags:     dns.ZONE | dns.SEP,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}

	zskDS := signer.zsk.ToDS(dns.SHA256)
	if zskDS == nil {
		return nil, fmt.Errorf("failed to generate DS record")
	}

	kskDS := signer.ksk.ToDS(dns.SHA256)
	if kskDS == nil {
		return nil, fmt.Errorf("failed to generate DS record")
	}

	signer.zskDS = *zskDS
	signer.kskDS = *kskDS

	for _, n := range ns {
		signer.ns = append(signer.ns, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   signer.zone,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    signer.ttl,
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
			sig, err := s.sign(rr, time.Now())
			if err != nil {
				return err
			}
			s.records[rr[0].Header().Rrtype].Store(&SignedAnswer{
				RR:  rr,
				Sig: sig,
			})
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

func (s *Signer) Transfer() (result []*SignedAnswer) {
	soa := s.soa.Load()
	if soa == nil {
		return
	}
	result = append(result, soa)
	for _, r := range s.records {
		if rr := r.Load(); rr != nil {
			result = append(result, rr)
		}
	}
	result = append(result, soa)
	return result
}

func (s *Signer) Get(rtype uint16) *SignedAnswer {
	if rtype == dns.TypeSOA {
		return s.soa.Load()
	}
	return s.records[rtype].Load()
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

func (s *Signer) DS() []*dns.DS {
	return []*dns.DS{
		&s.zskDS,
		&s.kskDS,
	}
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
			Name:   s.zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    s.ttl,
		},
		Ns:     s.ns[0].Ns,
		Mbox:   s.mailbox,
		Serial: uint32(now.Unix()),

		Refresh: s.refresh,
		Retry:   s.refresh / 2,
		Expire:  s.refresh * 100,
		Minttl:  s.ttl * 2,
	}
}

func (s *Signer) sign(rr []dns.RR, now time.Time) (sig *dns.RRSIG, err error) {
	var key = &s.zsk
	if rr[0].Header().Rrtype == dns.TypeDNSKEY {
		key = &s.ksk
	}

	sig = &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   key.Hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  key.Hdr.Class,
			Ttl:    s.ttl,
		},
		TypeCovered: rr[0].Header().Rrtype,
		Labels:      uint8(dns.CountLabel(rr[0].Header().Name)),
		OrigTtl:     rr[0].Header().Ttl,

		// oh DNS, still using uint32 for time??? at least it's not int32
		Expiration: uint32(now.Add(time.Second * time.Duration(s.ttl)).Unix()),
		Inception:  uint32(now.Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: key.Hdr.Name,
		Algorithm:  key.Algorithm,
	}

	if err = sig.Sign(s.key, rr); err != nil {
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
