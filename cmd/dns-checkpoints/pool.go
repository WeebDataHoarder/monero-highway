package main

import (
	"sync"

	"github.com/miekg/dns"
)

type ReplyPool struct {
	p sync.Pool
}

func NewReplyPool() *ReplyPool {
	p := &ReplyPool{}
	p.p.New = func() any {
		return new(dns.Msg)
	}

	return p
}

func (p *ReplyPool) Put(msg *dns.Msg) {
	// reset
	msg.Question = msg.Question[:0]
	msg.Answer = msg.Answer[:0]
	msg.Ns = msg.Ns[:0]
	msg.Extra = msg.Extra[:0]

	p.p.Put(msg)
}

func (p *ReplyPool) Get() *dns.Msg {
	return p.p.Get().(*dns.Msg)
}
