package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"git.gammaspectra.live/P2Pool/monero-highway/internal/utils"
	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/dns"
	"github.com/cloudflare/cloudflare-go/v6/option"

	"golang.org/x/net/proxy"
)

var cloudflareApiKey string

func init() {
	apiKey, ok := os.LookupEnv("CLOUDFLARE_API_TOKEN")
	if !ok {
		panic("CLOUDFLARE_API_TOKEN environment variable not set")
	}
	cloudflareApiKey = apiKey
}

func sendCloudflare(d proxy.ContextDialer, ctx context.Context, zoneId string, name string, ttl time.Duration, recordSet []string) error {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: d.DialContext,
		},
		Timeout: 30 * time.Second,
	}

	client := cloudflare.NewClient(
		option.WithHTTPClient(&httpClient),
		option.WithAPIToken(cloudflareApiKey),
	)

	// get old records to remove them
	records := client.DNS.Records.ListAutoPaging(ctx, dns.RecordListParams{
		ZoneID: cloudflare.F(zoneId),
		Match:  cloudflare.F(dns.RecordListParamsMatchAll),
		Name: cloudflare.F(dns.RecordListParamsName{
			Exact: cloudflare.F(name),
		}),
		Type: cloudflare.F(dns.RecordListParamsTypeTXT),
	})

	var deletes []dns.RecordBatchParamsDelete
	var posts []dns.RecordBatchParamsPostUnion

	for records.Next() {
		r := records.Current()
		// sanity check
		if r.Name != name || r.Type != dns.RecordResponseTypeTXT {
			continue
		}
		deletes = append(deletes, dns.RecordBatchParamsDelete{ID: cloudflare.F(r.ID)})
	}

	if err := records.Err(); err != nil {
		return err
	}

	for _, r := range recordSet {
		posts = append(posts, dns.TXTRecordParam{
			Name:    cloudflare.F(name),
			TTL:     cloudflare.F(dns.TTL(ttl / time.Second)),
			Type:    cloudflare.F(dns.TXTRecordTypeTXT),
			Content: cloudflare.F("\"" + r + "\""),
			Comment: cloudflare.F("managed by monero-highway"),
		})
	}

	_, err := client.DNS.Records.Batch(ctx,
		dns.RecordBatchParams{
			ZoneID:  cloudflare.F(zoneId),
			Deletes: cloudflare.F(deletes),
			Posts:   cloudflare.F(posts),
		},
	)
	return err
}

type ContextDialer interface {
	proxy.Dialer
	proxy.ContextDialer
}

func main() {
	zoneId := flag.String("zone-id", "", "Cloudflare Zone ID")
	name := flag.String("name", "", "Cloudflare Domain or Subdomain full name where to set records")
	ttl := flag.Duration("ttl", time.Minute, "TTL for TXT records")
	proxyStr := flag.String("proxy", "", "URL to use as a proxy, example socks5://127.0.0.1:9050")
	var recordSet utils.MultiStringFlag
	flag.Var(&recordSet, "txt", "TXT record entry, unquoted. Can be specified multiple times")

	flag.Parse()

	var dialer ContextDialer
	dialer = &net.Dialer{
		Timeout: time.Second * 30,
	}

	if *proxyStr != "" {
		uri, err := url.Parse(*proxyStr)
		if err != nil {
			panic(fmt.Errorf("invalid proxy URL: %s", err))
		}
		p, err := proxy.FromURL(uri, dialer)
		if err != nil {
			panic(fmt.Errorf("invalid proxy URL: %s", err))
		}
		if cd, ok := p.(ContextDialer); ok {
			dialer = cd
		} else {
			panic("proxy does not implement ContextDialer")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	err := sendCloudflare(dialer, ctx, *zoneId, *name, *ttl, recordSet)
	if err != nil {
		panic(fmt.Errorf("failed to set cloudflare records: %s", err))
	}
	println("OK")
}
