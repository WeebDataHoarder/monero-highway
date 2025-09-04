package main

import "github.com/miekg/dns"

func RequestHandler(signer *Signer, handleAXFR bool) dns.HandlerFunc {
	p := NewReplyPool()

	return func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 || r.Opcode != dns.OpcodeQuery {
			return
		}

		msg := p.Get()
		defer p.Put(msg)

		var validQuery bool

		for _, q := range r.Question {
			if q.Qclass == dns.ClassINET && dns.CanonicalName(q.Name) == signer.Zone() {
				validQuery = true
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
						msg.SetEdns0(4096, true)
					}
					// disallow multiple queries to same match
					break
				} else if q.Qtype == dns.TypeAXFR && handleAXFR {

					var isDNSSEC bool
					if dns0 := r.IsEdns0(); dns0 != nil {
						isDNSSEC = dns0.Do()
					}
					msg.Authoritative = true
					for _, answer := range signer.Transfer() {
						msg.Answer = append(msg.Answer, answer.RR...)
						if isDNSSEC {
							msg.Answer = append(msg.Answer, answer.Sig)
							msg.SetEdns0(4096, true)
						}
					}
					// disallow multiple queries to same match
					break
				}
			}
		}

		if len(msg.Answer) > 0 || validQuery {
			// only set reply at the end
			msg.SetReply(r)
			_ = w.WriteMsg(msg)
		} else {
			msg.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(msg)
		}
	}
}
