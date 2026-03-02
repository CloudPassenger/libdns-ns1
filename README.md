# NS1 for `libdns`

This package implements the [`libdns`](https://github.com/libdns/libdns) interfaces for NS1,
allowing you to manage DNS records through the NS1 HTTP API.

Maintainer: CloudPassenger

## Features

- Uses NS1 HTTP API directly (no third-party NS1 SDK dependency)
- Supports standard `libdns.Record` fields (`Type`, `Name`, `Data`, `TTL`)
- `AppendRecords`: merges answers into existing NS1 record sets
- `SetRecords`: overwrites answer sets for each `(name, type)`
- `DeleteRecords`: ignores non-existent input records and continues
- `ListZones`: supported via `libdns.ZoneLister`

## Behavior notes

- Record names are handled as `libdns` relative names (`@`, `www`, etc.) and converted to
  NS1 FQDNs internally.
- `AppendRecords` and `SetRecords` operate on NS1 record sets (`answers`) grouped by `(name, type)`.
- `DeleteRecords` follows `libdns` semantics: non-existent targets are ignored.

## Configuration

```go
provider := &ns1.Provider{
    APIKey: "<ns1-api-key>",
    // Optional:
    // Endpoint: "https://api.nsone.net/v1/",
    // Timeout:  10 * time.Second,
}
```

### Fields

- `APIKey` (required): NS1 API key
- `Endpoint` (optional): NS1 API endpoint (defaults to `https://api.nsone.net/v1/`)
- `Timeout` (optional): request timeout (defaults to 10s)

## Minimal usage example

```go
package main

import (
	"context"
	"fmt"
	"time"

	ns1 "github.com/CloudPassenger/libdns-ns1"
	"github.com/libdns/libdns"
)

func main() {
	ctx := context.Background()
	zone := "example.com."

	p := &ns1.Provider{
		APIKey: "${NS1_API_KEY}",
		Timeout: 10 * time.Second,
	}

	// Set: overwrite records for (name,type)
	_, err := p.SetRecords(ctx, zone, []libdns.Record{
		libdns.RR{Name: "www", Type: "A", Data: "203.0.113.10", TTL: 300 * time.Second},
		libdns.RR{Name: "www", Type: "A", Data: "203.0.113.11", TTL: 300 * time.Second},
	})
	if err != nil {
		panic(err)
	}

	// Append: merge into existing answers for (name,type)
	_, err = p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.RR{Name: "www", Type: "A", Data: "203.0.113.12", TTL: 300 * time.Second},
	})
	if err != nil {
		panic(err)
	}

	recs, err := p.GetRecords(ctx, zone)
	if err != nil {
		panic(err)
	}

	for _, rec := range recs {
		rr := rec.RR()
		fmt.Printf("%s %s %s %s\n", rr.Name, rr.TTL, rr.Type, rr.Data)
	}
}
```

## Testing

### Unit tests

From repository root:

```bash
go test ./...
```

### Integration tests (Cloudflare-style `libdnstest` module)

This repository includes a dedicated `libdnstest/` module similar to other mature `libdns` providers.

Required environment variables:

- `NS1_API_KEY`
- `NS1_TEST_ZONE` (must be FQDN with trailing dot, e.g. `example.com.`)

Optional:

- `NS1_API_ENDPOINT` (for non-default environments)

Run:

```bash
cd libdnstest
go test ./...
```
