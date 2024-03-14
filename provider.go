package ns1

import (
	"context"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with ns1.
type Provider struct {
	Client
	// struct tags on exported fields), for example:
	APIKey  string        `json:"api_key,omitempty"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {

	p.mutex.Lock()
	defer p.mutex.Unlock()

	records, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var createdRecords []libdns.Record

	for _, record := range records {
		createdRecord, err := p.createOrUpdateRecord(ctx, zone, record)
		if err != nil {
			return nil, err
		}
		createdRecords = append(createdRecords, createdRecord)
	}

	return createdRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var updatedRecords []libdns.Record

	for _, record := range records {
		updatedRecord, err := p.createOrUpdateRecord(ctx, zone, record)
		if err != nil {
			return nil, err
		}
		updatedRecords = append(updatedRecords, updatedRecord)
	}

	return updatedRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deletedRecords []libdns.Record

	for _, record := range records {
		deletedRecord, err := p.deleteRecord(ctx, zone, record)
		if err != nil {
			return nil, err
		}
		deletedRecords = append(deletedRecords, deletedRecord)
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
