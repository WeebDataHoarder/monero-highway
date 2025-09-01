package checkpoint

import (
	"context"
	"fmt"

	"golang.org/x/net/proxy"
)

type Method string

const (
	// MethodHighwayDNS Use cmd/dns-checkpoints api
	MethodHighwayDNS = "highway-dns"
	// MethodCloudflare Uses Cloudflare's dns_records batch api
	MethodCloudflare = "cloudflare"
	// MethodNjalla Uses Njalla's JSON-RPC API https://njal.la/api/
	MethodNjalla = "njalla"
)

type Config struct {
	Method Method            `yaml:"method"`
	Config map[string]string `yaml:"config"`
}

func (cc Config) Send(d proxy.ContextDialer, ctx context.Context, c Checkpoints) error {
	switch cc.Method {
	case MethodHighwayDNS:
		return cc.sendHighway(d, ctx, c)

	case MethodCloudflare:
		return cc.sendCloudflare(d, ctx, c)
	case MethodNjalla:
		//TODO
		fallthrough
	default:
		return fmt.Errorf("unknown checkpoint method %s", cc.Method)
	}
}
