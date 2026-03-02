package ns1

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// HTTPClient is the client used for outbound API calls.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Provider facilitates DNS record manipulation with ns1.
type Provider struct {
	APIKey   string        `json:"api_key,omitempty"`
	Endpoint string        `json:"endpoint,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`

	// HTTPClient is the HTTP client used to communicate with NS1.
	// If nil, a default client will be used.
	HTTPClient HTTPClient `json:"-"`

	mutex  sync.Mutex
	client *ns1Client
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	return p.getRecords(ctx, zone)
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if err := p.init(); err != nil {
		return nil, err
	}

	grouped := groupRecordsBySet(zone, records)
	keys := sortedGroupKeys(grouped)

	created := make([]libdns.Record, 0, len(records))
	for _, key := range keys {
		group := grouped[key]
		answers, desired, ttl, err := desiredAnswersForInput(group)
		if err != nil {
			return nil, err
		}

		existing, err := p.client.getRecord(ctx, key.zone, key.domain, key.rtype)
		if err != nil && !isNotFoundError(err, "record not found") {
			return nil, err
		}

		if err != nil {
			if _, err = p.client.createRecord(ctx, key.zone, key.domain, key.rtype, ns1RecordSetWrite{
				TTL:     ttl,
				Answers: answers,
			}); err != nil {
				return nil, err
			}
			created = append(created, desired...)
			continue
		}

		existingSet := answerSignatureSet(existing.Answers)
		merged := append([]ns1Answer(nil), existing.Answers...)
		newlyAdded := make([]libdns.Record, 0, len(desired))

		for i, ans := range answers {
			sig := signatureFromFields(ans.Answer)
			if _, ok := existingSet[sig]; ok {
				continue
			}
			existingSet[sig] = struct{}{}
			merged = append(merged, ans)
			newlyAdded = append(newlyAdded, desired[i])
		}

		if len(newlyAdded) == 0 {
			continue
		}

		effectiveTTL := ttl
		if effectiveTTL == 0 {
			effectiveTTL = existing.TTL
		}

		if _, err = p.client.updateRecord(ctx, key.zone, key.domain, key.rtype, ns1RecordSetWrite{
			TTL:     effectiveTTL,
			Answers: merged,
		}); err != nil {
			return nil, err
		}

		created = append(created, newlyAdded...)
	}

	return created, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if err := p.init(); err != nil {
		return nil, err
	}

	grouped := groupRecordsBySet(zone, records)
	keys := sortedGroupKeys(grouped)

	updated := make([]libdns.Record, 0, len(records))
	for _, key := range keys {
		group := grouped[key]
		answers, desired, ttl, err := desiredAnswersForInput(group)
		if err != nil {
			return nil, err
		}

		existing, err := p.client.getRecord(ctx, key.zone, key.domain, key.rtype)
		if err != nil && !isNotFoundError(err, "record not found") {
			return nil, err
		}

		if err != nil {
			if _, err = p.client.createRecord(ctx, key.zone, key.domain, key.rtype, ns1RecordSetWrite{
				TTL:     ttl,
				Answers: answers,
			}); err != nil {
				return nil, err
			}
			updated = append(updated, desired...)
			continue
		}

		effectiveTTL := ttl
		if effectiveTTL == 0 {
			effectiveTTL = existing.TTL
		}

		if existing.TTL != effectiveTTL || !answersEqual(existing.Answers, answers) {
			if _, err = p.client.updateRecord(ctx, key.zone, key.domain, key.rtype, ns1RecordSetWrite{
				TTL:     effectiveTTL,
				Answers: answers,
			}); err != nil {
				return nil, err
			}
		}

		updated = append(updated, desired...)
	}

	return updated, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if err := p.init(); err != nil {
		return nil, err
	}

	current, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	matched := make(map[recordSetKey]map[string]libdns.Record)
	for _, candidate := range records {
		candRR := candidate.RR()
		for _, existing := range current {
			existingRR := existing.RR()
			if existingRR.Name != candRR.Name {
				continue
			}
			if candRR.Type != "" && !strings.EqualFold(existingRR.Type, candRR.Type) {
				continue
			}
			if candRR.TTL != 0 && existingRR.TTL != candRR.TTL {
				continue
			}
			if candRR.Data != "" && existingRR.Data != candRR.Data {
				continue
			}

			key := recordSetKey{
				zone:   normalizeZone(zone),
				domain: absoluteDomain(zone, existingRR.Name),
				rtype:  strings.ToUpper(existingRR.Type),
			}
			if _, ok := matched[key]; !ok {
				matched[key] = make(map[string]libdns.Record)
			}
			matched[key][recordExactSignature(existingRR)] = existing
		}
	}

	if len(matched) == 0 {
		return nil, nil
	}

	deleted := make([]libdns.Record, 0)
	for key, bySig := range matched {
		existing, err := p.client.getRecord(ctx, key.zone, key.domain, key.rtype)
		if err != nil {
			if isNotFoundError(err, "record not found") {
				continue
			}
			return nil, err
		}

		keptAnswers := make([]ns1Answer, 0, len(existing.Answers))
		for _, ans := range existing.Answers {
			rr := libdns.RR{
				Name: relativeDomain(zone, key.domain),
				Type: key.rtype,
				TTL:  time.Duration(existing.TTL) * time.Second,
				Data: answerData(ans),
			}

			sig := recordExactSignature(rr)
			if rec, ok := bySig[sig]; ok {
				deleted = append(deleted, rec)
				continue
			}

			keptAnswers = append(keptAnswers, ans)
		}

		if len(keptAnswers) == len(existing.Answers) {
			continue
		}

		if len(keptAnswers) == 0 {
			err = p.client.deleteRecord(ctx, key.zone, key.domain, key.rtype)
			if err != nil && !isNotFoundError(err, "record not found") {
				return nil, err
			}
			continue
		}

		if _, err = p.client.updateRecord(ctx, key.zone, key.domain, key.rtype, ns1RecordSetWrite{
			TTL:     existing.TTL,
			Answers: keptAnswers,
		}); err != nil {
			return nil, err
		}
	}

	return deleted, nil
}

// ListZones lists available zones for this account.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if err := p.init(); err != nil {
		return nil, err
	}

	zones, err := p.client.listZones(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]libdns.Zone, 0, len(zones))
	for _, z := range zones {
		if z.Zone == "" {
			continue
		}
		out = append(out, libdns.Zone{Name: ToFqdn(z.Zone)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (p *Provider) init() error {
	if p.client != nil {
		return nil
	}
	if p.APIKey == "" {
		return fmt.Errorf("API key is missing")
	}

	timeout := p.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	httpClient := p.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}

	p.client = newNS1Client(httpClient, p.Endpoint, p.APIKey)
	return nil
}

func (p *Provider) getRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if err := p.init(); err != nil {
		return nil, err
	}

	detail, err := p.client.getZone(ctx, normalizeZone(zone), true)
	if err != nil {
		return nil, err
	}

	return toLibdnsRecords(zone, detail.Records)
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
