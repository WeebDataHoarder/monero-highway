package main

import "github.com/miekg/dns"

func RequestHandler(signer *Signer, udp bool, handleAXFR bool, udpBufferSize uint16) dns.HandlerFunc {
	p := NewReplyPool()

	return func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 || r.Opcode != dns.OpcodeQuery {
			return
		}

		msg := p.Get()
		defer p.Put(msg)
		msg.SetReply(r)

		dns0 := r.IsEdns0()
		if dns0 != nil {
			if dns0.Version() != 0 {
				msg.SetEdns0(udpBufferSize, false)
				msg.SetRcode(r, dns.RcodeBadVers)
				_ = w.WriteMsg(msg)
				return
			}

			msg.SetEdns0(udpBufferSize, dns0.Do())
		}

		zoneLabels := len(signer.ZoneLabels())

		for _, q := range r.Question {
			if q.Qclass == dns.ClassINET && dns.CompareDomainName(q.Name, signer.Zone()) == zoneLabels {
				if cnt := dns.CountLabel(q.Name); cnt == zoneLabels {
					msg.Authoritative = true

					answer := signer.Get(q.Qtype)
					if answer != nil {
						msg.Answer = append(msg.Answer, answer.RR...)
						if dns0 != nil && dns0.Do() {
							msg.Answer = append(msg.Answer, answer.Sig)
						}
					} else if q.Qtype == dns.TypeAXFR && handleAXFR && !udp {
						for _, answer := range signer.Transfer() {
							// always send DNSSEC records here
							msg.Answer = append(msg.Answer, answer.RR...)
							if answer.Sig != nil && (dns0 == nil /* special case for HE */ || (dns0 != nil && dns0.Do())) {
								msg.Answer = append(msg.Answer, answer.Sig)
							}
						}
						if dns0 == nil {
							// set DO flags
							msg.SetEdns0(udpBufferSize, true)
						}
					} else {
						if dns0 != nil && dns0.Do() {
							soa := signer.Get(dns.TypeSOA)
							msg.Ns = append(msg.Ns, soa.RR...)
							msg.Ns = append(msg.Ns, soa.Sig)
							nsec := signer.Get(dns.TypeNSEC)
							msg.Ns = append(msg.Ns, nsec.RR...)
							msg.Ns = append(msg.Ns, nsec.Sig)
						}
					}
					// disallow multiple queries to same match
					break
				} else if cnt > zoneLabels {
					msg.Authoritative = true
					msg.SetRcode(r, dns.RcodeNameError)
					if dns0 != nil && dns0.Do() {
						soa := signer.Get(dns.TypeSOA)
						msg.Ns = append(msg.Ns, soa.RR...)
						msg.Ns = append(msg.Ns, soa.Sig)
						nsec := signer.Get(dns.TypeNSEC)
						msg.Ns = append(msg.Ns, nsec.RR...)
						msg.Ns = append(msg.Ns, nsec.Sig)
					}
					break
				} else {
					msg.SetRcode(r, dns.RcodeRefused)
					break
				}
			}
		}

		if udp {
			if dns0 != nil {
				msg.Truncate(int(dns0.UDPSize()))
			} else {
				msg.Truncate(dns.MinMsgSize)
			}
		}

		_ = w.WriteMsg(msg)
	}
}
