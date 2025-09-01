package checkpoint

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/dns"
	"github.com/cloudflare/cloudflare-go/v6/option"
	"golang.org/x/net/proxy"
)

func (cc Config) sendCloudflare(d proxy.ContextDialer, ctx context.Context, c Checkpoints) error {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: d.DialContext,
		},
		Timeout: 30 * time.Second,
	}

	apiToken, ok := os.LookupEnv("CLOUDFLARE_API_TOKEN")
	if !ok {
		apiToken = cc.Config["api-token"]
	}
	client := cloudflare.NewClient(
		option.WithHTTPClient(&httpClient),
		option.WithAPIToken(apiToken),
	)

	ttl, err := strconv.Atoi(cc.Config["ttl"])
	if err != nil {
		return err
	}

	// get old records to remove them
	records := client.DNS.Records.ListAutoPaging(ctx, dns.RecordListParams{
		ZoneID: cloudflare.F(cc.Config["zone-id"]),
		Match:  cloudflare.F(dns.RecordListParamsMatchAll),
		Name: cloudflare.F(dns.RecordListParamsName{
			Exact: cloudflare.F(cc.Config["name"]),
		}),
		Type: cloudflare.F(dns.RecordListParamsTypeTXT),
	})

	var deletes []dns.RecordBatchParamsDelete
	var posts []dns.RecordBatchParamsPostUnion

	for records.Next() {
		r := records.Current()
		// sanity check
		if r.Name != cc.Config["name"] || r.Type != dns.RecordResponseTypeTXT {
			continue
		}
		deletes = append(deletes, dns.RecordBatchParamsDelete{ID: cloudflare.F(r.ID)})
	}

	if err := records.Err(); err != nil {
		return err
	}

	for _, r := range c {
		posts = append(posts, dns.TXTRecordParam{
			Name:    cloudflare.F(cc.Config["name"]),
			TTL:     cloudflare.F(dns.TTL(ttl)),
			Type:    cloudflare.F(dns.TXTRecordTypeTXT),
			Content: cloudflare.F("\"" + r.String() + "\""),
			Comment: cloudflare.F("managed by monero-highway"),
		})
	}

	_, err = client.DNS.Records.Batch(ctx,
		dns.RecordBatchParams{
			ZoneID:  cloudflare.F(cc.Config["zone-id"]),
			Deletes: cloudflare.F(deletes),
			Posts:   cloudflare.F(posts),
		},
	)
	return err
}
