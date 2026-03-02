package ns1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

const defaultEndpoint = "https://api.nsone.net/v1/"

type ns1Client struct {
	httpClient HTTPClient
	endpoint   string
	apiKey     string
}

type ns1APIError struct {
	StatusCode int
	Message    string
}

func (e *ns1APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("got error status: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("got error status: HTTP %d: %s", e.StatusCode, e.Message)
}

type ns1Zone struct {
	Zone string `json:"zone"`
}

type ns1ZoneRecord struct {
	Domain       string   `json:"domain"`
	Type         string   `json:"type"`
	TTL          int      `json:"ttl"`
	ShortAnswers []string `json:"short_answers,omitempty"`
}

type ns1ZoneDetails struct {
	Zone    string          `json:"zone"`
	Records []ns1ZoneRecord `json:"records,omitempty"`
}

type ns1Answer struct {
	Answer []any `json:"answer"`
}

type ns1RecordSet struct {
	Zone    string      `json:"zone"`
	Domain  string      `json:"domain"`
	Type    string      `json:"type"`
	TTL     int         `json:"ttl"`
	Answers []ns1Answer `json:"answers"`
}

type ns1RecordSetWrite struct {
	TTL     int         `json:"ttl,omitempty"`
	Answers []ns1Answer `json:"answers"`
}

type recordSetKey struct {
	zone   string
	domain string
	rtype  string
}

func newNS1Client(httpClient HTTPClient, endpoint, apiKey string) *ns1Client {
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}

	return &ns1Client{
		httpClient: httpClient,
		endpoint:   endpoint,
		apiKey:     apiKey,
	}
}

func (c *ns1Client) listZones(ctx context.Context) ([]ns1Zone, error) {
	var zones []ns1Zone
	if err := c.doJSON(ctx, http.MethodGet, "zones", nil, &zones); err != nil {
		return nil, err
	}
	return zones, nil
}

func (c *ns1Client) getZone(ctx context.Context, zone string, includeRecords bool) (ns1ZoneDetails, error) {
	path := fmt.Sprintf("zones/%s?records=%t", url.PathEscape(zone), includeRecords)
	var out ns1ZoneDetails
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return ns1ZoneDetails{}, err
	}
	return out, nil
}

func (c *ns1Client) getRecord(ctx context.Context, zone, domain, rtype string) (ns1RecordSet, error) {
	var out ns1RecordSet
	if err := c.doJSON(ctx, http.MethodGet, recordPath(zone, domain, rtype), nil, &out); err != nil {
		return ns1RecordSet{}, err
	}
	return out, nil
}

func (c *ns1Client) createRecord(ctx context.Context, zone, domain, rtype string, payload ns1RecordSetWrite) (ns1RecordSet, error) {
	var out ns1RecordSet
	if err := c.doJSON(ctx, http.MethodPut, recordPath(zone, domain, rtype), payload, &out); err != nil {
		return ns1RecordSet{}, err
	}
	return out, nil
}

func (c *ns1Client) updateRecord(ctx context.Context, zone, domain, rtype string, payload ns1RecordSetWrite) (ns1RecordSet, error) {
	var out ns1RecordSet
	if err := c.doJSON(ctx, http.MethodPost, recordPath(zone, domain, rtype), payload, &out); err != nil {
		return ns1RecordSet{}, err
	}
	return out, nil
}

func (c *ns1Client) deleteRecord(ctx context.Context, zone, domain, rtype string) error {
	return c.doJSON(ctx, http.MethodDelete, recordPath(zone, domain, rtype), nil, nil)
}

func recordPath(zone, domain, rtype string) string {
	return fmt.Sprintf("zones/%s/%s/%s", url.PathEscape(zone), url.PathEscape(domain), url.PathEscape(strings.ToUpper(rtype)))
}

func (c *ns1Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+strings.TrimPrefix(path, "/"), reqBody)
	if err != nil {
		return err
	}

	req.Header.Set("X-NSONE-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(data))
		if len(data) > 0 {
			var payload struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(data, &payload) == nil && payload.Message != "" {
				msg = payload.Message
			}
		}
		return &ns1APIError{StatusCode: resp.StatusCode, Message: msg}
	}

	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func isNotFoundError(err error, contains string) bool {
	var apiErr *ns1APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode != http.StatusNotFound {
		return false
	}
	return strings.Contains(strings.ToLower(apiErr.Message), strings.ToLower(contains))
}

func toLibdnsRecords(zone string, recordSets []ns1ZoneRecord) ([]libdns.Record, error) {
	records := make([]libdns.Record, 0)
	for _, set := range recordSets {
		for _, ans := range set.ShortAnswers {
			rr := libdns.RR{
				Type: set.Type,
				Name: relativeDomain(zone, set.Domain),
				Data: ans,
				TTL:  time.Duration(set.TTL) * time.Second,
			}

			rec, err := rr.Parse()
			if err != nil {
				return nil, err
			}
			records = append(records, rec)
		}
	}

	return records, nil
}

func groupRecordsBySet(zone string, records []libdns.Record) map[recordSetKey][]libdns.Record {
	grouped := make(map[recordSetKey][]libdns.Record)
	for _, record := range records {
		rr := record.RR()
		key := recordSetKey{
			zone:   normalizeZone(zone),
			domain: absoluteDomain(zone, rr.Name),
			rtype:  strings.ToUpper(rr.Type),
		}
		grouped[key] = append(grouped[key], record)
	}
	return grouped
}

func sortedGroupKeys(grouped map[recordSetKey][]libdns.Record) []recordSetKey {
	keys := make([]recordSetKey, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].domain != keys[j].domain {
			return keys[i].domain < keys[j].domain
		}
		return keys[i].rtype < keys[j].rtype
	})
	return keys
}

func desiredAnswersForInput(group []libdns.Record) ([]ns1Answer, []libdns.Record, int, error) {
	answers := make([]ns1Answer, 0, len(group))
	desired := make([]libdns.Record, 0, len(group))
	seen := make(map[string]struct{})

	ttl := 0
	for _, record := range group {
		rr := record.RR()
		if strings.TrimSpace(rr.Type) == "" {
			return nil, nil, 0, fmt.Errorf("record type is required")
		}
		if ttl == 0 && rr.TTL > 0 {
			ttl = int(rr.TTL / time.Second)
		}

		fields, err := answerFieldsFromRecord(record)
		if err != nil {
			return nil, nil, 0, err
		}

		sig := signatureFromFields(fields)
		if _, ok := seen[sig]; ok {
			continue
		}
		seen[sig] = struct{}{}

		answers = append(answers, ns1Answer{Answer: fields})

		parsed, err := rr.Parse()
		if err != nil {
			return nil, nil, 0, err
		}
		desired = append(desired, parsed)
	}

	if len(answers) == 0 {
		return nil, nil, 0, fmt.Errorf("no records to apply")
	}

	return answers, desired, ttl, nil
}

func answerFieldsFromRecord(record libdns.Record) ([]any, error) {
	switch r := record.(type) {
	case libdns.Address:
		return []any{r.IP.String()}, nil
	case libdns.CNAME:
		return []any{r.Target}, nil
	case libdns.NS:
		return []any{r.Target}, nil
	case libdns.TXT:
		return []any{r.Text}, nil
	case libdns.MX:
		return []any{int(r.Preference), r.Target}, nil
	case libdns.SRV:
		return []any{int(r.Priority), int(r.Weight), int(r.Port), r.Target}, nil
	case libdns.CAA:
		return []any{int(r.Flags), r.Tag, r.Value}, nil
	default:
		rr := record.RR()
		typeName := strings.ToUpper(rr.Type)
		switch typeName {
		case "TXT", "A", "AAAA", "CNAME", "NS":
			return []any{rr.Data}, nil
		case "MX", "SRV", "CAA":
			parts := strings.Fields(rr.Data)
			if len(parts) == 0 {
				return nil, fmt.Errorf("empty rdata for %s", typeName)
			}
			out := make([]any, 0, len(parts))
			for _, p := range parts {
				out = append(out, p)
			}
			return out, nil
		default:
			if strings.TrimSpace(rr.Data) == "" {
				return nil, fmt.Errorf("empty rdata for %s", typeName)
			}
			return []any{rr.Data}, nil
		}
	}
}

func answersEqual(a, b []ns1Answer) bool {
	if len(a) != len(b) {
		return false
	}
	set := answerSignatureSet(a)
	for _, ans := range b {
		if _, ok := set[signatureFromFields(ans.Answer)]; !ok {
			return false
		}
	}
	return true
}

func answerSignatureSet(answers []ns1Answer) map[string]struct{} {
	set := make(map[string]struct{}, len(answers))
	for _, ans := range answers {
		set[signatureFromFields(ans.Answer)] = struct{}{}
	}
	return set
}

func signatureFromFields(fields []any) string {
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		parts = append(parts, stringifyAnswerValue(field))
	}
	return strings.Join(parts, "\x1f")
}

func answerData(ans ns1Answer) string {
	parts := make([]string, 0, len(ans.Answer))
	for _, field := range ans.Answer {
		parts = append(parts, stringifyAnswerValue(field))
	}
	return strings.Join(parts, " ")
}

func stringifyAnswerValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

func recordExactSignature(rr libdns.RR) string {
	return strings.Join([]string{
		rr.Name,
		strings.ToUpper(rr.Type),
		strconv.FormatInt(rr.TTL.Nanoseconds(), 10),
		rr.Data,
	}, "\x1e")
}

func normalizeZone(zone string) string {
	return UnFqdn(strings.TrimSpace(zone))
}

func absoluteDomain(zone, name string) string {
	return UnFqdn(libdns.AbsoluteName(name, ToFqdn(normalizeZone(zone))))
}

func relativeDomain(zone, domain string) string {
	return libdns.RelativeName(ToFqdn(domain), ToFqdn(normalizeZone(zone)))
}

// ToFqdn converts the name into a fqdn appending a trailing dot.
func ToFqdn(name string) string {
	n := len(name)
	if n == 0 || name[n-1] == '.' {
		return name
	}
	return name + "."
}

// UnFqdn converts the fqdn into a name removing the trailing dot.
func UnFqdn(name string) string {
	n := len(name)
	if n != 0 && name[n-1] == '.' {
		return name[:n-1]
	}
	return name
}
