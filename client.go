package ns1

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/libdns/libdns"
	api "gopkg.in/ns1/ns1-go.v2/rest"
	"gopkg.in/ns1/ns1-go.v2/rest/model/dns"
)

type Client struct {
	client *api.Client
	mutex  sync.Mutex
}

// init initializes the NS1 client.
func (p *Provider) init() error {
	if p.client != nil {
		return nil
	}

	if p.APIKey == "" {
		// Missing API key
		return fmt.Errorf("ns1: API Key is missing")
	}

	if p.Timeout == 0 {
		p.Timeout = 10 * time.Second
	}

	httpClient := &http.Client{Timeout: p.Timeout}
	p.client = api.NewClient(httpClient, api.SetAPIKey(p.APIKey))

	return nil
}

func (p *Provider) getRecords(_ context.Context, zone string) ([]libdns.Record, error) {

	p.mutex.Lock()
	defer p.mutex.Unlock()

	err := p.init()
	if err != nil {
		return nil, err
	}

	detail, _, err := p.client.Zones.Get(zone, true)
	if err != nil {
		return nil, err
	}

	records := convertNS1ZoneRecordsToLibdnsRecords(detail.Records)

	return records, nil
}

func (p *Provider) createOrUpdateRecord(ctx context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	err := p.init()
	if err != nil {
		return record, err
	}

	if record.ID == "" {
		return p.createRecord(ctx, zone, record)
	} else {
		return p.updateRecord(ctx, zone, record)
	}

}

func (p *Provider) createRecord(_ context.Context, zone string, record libdns.Record) (libdns.Record, error) {

	recordSet := convertLibdnsRecordToNS1Record(zone, record)
	_, err := p.client.Records.Create(recordSet)
	if err != nil {
		return record, err
	}

	return record, nil
}

func (p *Provider) updateRecord(_ context.Context, zone string, record libdns.Record) (libdns.Record, error) {

	recordSet := convertLibdnsRecordToNS1Record(zone, record)
	_, err := p.client.Records.Update(recordSet)
	if err != nil {
		return record, err
	}

	return record, nil

}

func (p *Provider) deleteRecord(_ context.Context, zone string, record libdns.Record) (libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	err := p.init()
	if err != nil {
		return record, err
	}

	_, err = p.client.Records.Delete(zone, record.Name, record.Type)
	if err != nil {
		return record, err
	}

	return record, nil

}

func convertNS1ZoneRecordsToLibdnsRecords(recordSets []*dns.ZoneRecord) []libdns.Record {
	var records []libdns.Record

	for _, recordSet := range recordSets {
		record := convertNS1ZoneRecordToLibdnsRecord(recordSet)
		records = append(records, record)
	}

	return records
}

func convertNS1ZoneRecordToLibdnsRecord(recordSet *dns.ZoneRecord) libdns.Record {

	zoneRecord := libdns.Record{
		ID:    recordSet.ID,
		Type:  recordSet.Type,
		Name:  recordSet.Domain,
		Value: recordSet.ShortAns[0], // TODO: handle multiple answers, but seems no need
		TTL:   time.Duration(recordSet.TTL) * time.Second,
	}
	return zoneRecord
}

func convertLibdnsRecordToNS1Record(zone string, record libdns.Record) *dns.Record {

	answer := &dns.Answer{
		Rdata: []string{record.Value},
	}

	recordSet := &dns.Record{
		ID:      record.ID,
		Zone:    zone,
		Domain:  record.Name,
		Type:    record.Type,
		Answers: []*dns.Answer{answer},
		TTL:     int(record.TTL.Seconds()),
	}
	return recordSet
}
