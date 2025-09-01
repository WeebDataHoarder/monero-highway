package checkpoint

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

func (cc Config) sendHighway(d proxy.ContextDialer, ctx context.Context, c Checkpoints) error {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: d.DialContext,
		},
		Timeout: 30 * time.Second,
	}
	uri, err := url.Parse(cc.Config["url"])
	if err != nil {
		return err
	}
	values := uri.Query()
	delete(values, "txt")

	for _, r := range c {
		values.Add("txt", r.String())
	}
	uri.RawQuery = values.Encode()
	req, err := http.NewRequest(http.MethodPost, uri.String(), nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)

	r, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	defer io.ReadAll(r.Body)

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("checkpointer returned non-200 status code: %d", r.StatusCode)
	}
	return nil
}
