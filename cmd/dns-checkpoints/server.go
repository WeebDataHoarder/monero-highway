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

		var isDNSSEC bool
		dns0 := r.IsEdns0()
		if dns0 != nil {
			if dns0.Version() != 0 {
				msg.SetEdns0(udpBufferSize, false)
				msg.SetRcode(r, dns.RcodeBadVers)
				_ = w.WriteMsg(msg)
				return
			}

			isDNSSEC = dns0.Do()
			msg.SetEdns0(udpBufferSize, isDNSSEC)
		}

		var validQuery bool

		for _, q := range r.Question {
			if q.Qclass == dns.ClassINET && dns.CanonicalName(q.Name) == signer.Zone() {
				validQuery = true
				answer := signer.Get(q.Qtype)
				if answer != nil {
					msg.Authoritative = true
					msg.Answer = append(msg.Answer, answer.RR...)
					if isDNSSEC {
						msg.Answer = append(msg.Answer, answer.Sig)
					}
					// disallow multiple queries to same match
					break
				} else if q.Qtype == dns.TypeAXFR && handleAXFR {
					msg.Authoritative = true
					for _, answer := range signer.Transfer() {
						// always send DNSSEC records here
						msg.Answer = append(msg.Answer, answer.RR...)
						msg.Answer = append(msg.Answer, answer.Sig)
					}
					// disallow multiple queries to same match
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

		if len(msg.Answer) > 0 || validQuery {
			// only set reply at the end
			_ = w.WriteMsg(msg)
		} else {
			msg.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(msg)
		}
	}
}
