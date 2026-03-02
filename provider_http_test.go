package ns1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

type mockRecordSet struct {
	Zone    string
	Domain  string
	Type    string
	TTL     int
	Answers [][]string
}

type mockNS1Server struct {
	t      *testing.T
	apiKey string

	mu      sync.Mutex
	zones   []string
	records map[string]mockRecordSet
}

func newMockNS1Server(t *testing.T, apiKey string) *mockNS1Server {
	t.Helper()
	return &mockNS1Server{
		t:       t,
		apiKey:  apiKey,
		zones:   []string{"example.com", "example.net"},
		records: make(map[string]mockRecordSet),
	}
}

func (s *mockNS1Server) key(domain, rtype string) string {
	return strings.ToLower(domain) + "|" + strings.ToUpper(rtype)
}

func (s *mockNS1Server) setRecord(zone, domain, rtype string, ttl int, answers ...[]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[s.key(domain, rtype)] = mockRecordSet{
		Zone:    zone,
		Domain:  domain,
		Type:    strings.ToUpper(rtype),
		TTL:     ttl,
		Answers: answers,
	}
}

func (s *mockNS1Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("X-NSONE-Key"); got != s.apiKey {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "unauthorized"})
		return
	}

	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	segs := strings.Split(path, "/")
	if len(segs) == 0 || segs[0] != "zones" {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
		return
	}

	switch {
	case len(segs) == 1 && r.Method == http.MethodGet:
		s.handleListZones(w)
		return
	case len(segs) == 2 && r.Method == http.MethodGet:
		s.handleGetZone(w, segs[1], r.URL.Query().Get("records") != "false")
		return
	case len(segs) == 4:
		s.handleRecord(w, r, segs[1], segs[2], segs[3])
		return
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "not found"})
	}
}

func (s *mockNS1Server) handleListZones(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()

	type zone struct {
		Zone string `json:"zone"`
	}
	out := make([]zone, 0, len(s.zones))
	for _, z := range s.zones {
		out = append(out, zone{Zone: z})
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (s *mockNS1Server) handleGetZone(w http.ResponseWriter, zone string, includeRecords bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	type zoneRecord struct {
		Domain      string   `json:"domain"`
		Type        string   `json:"type"`
		TTL         int      `json:"ttl"`
		ShortAnswer []string `json:"short_answers"`
	}
	type zoneResp struct {
		Zone    string       `json:"zone"`
		Records []zoneRecord `json:"records,omitempty"`
	}

	resp := zoneResp{Zone: zone}
	if includeRecords {
		for _, rs := range s.records {
			if rs.Zone != zone {
				continue
			}
			short := make([]string, 0, len(rs.Answers))
			for _, ans := range rs.Answers {
				short = append(short, strings.Join(ans, " "))
			}
			resp.Records = append(resp.Records, zoneRecord{
				Domain:      rs.Domain,
				Type:        rs.Type,
				TTL:         rs.TTL,
				ShortAnswer: short,
			})
		}
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func (s *mockNS1Server) handleRecord(w http.ResponseWriter, r *http.Request, zone, domain, rtype string) {
	key := s.key(domain, rtype)

	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		rs, ok := s.records[key]
		s.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "record not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(toRecordResponse(rs))
	case http.MethodPut, http.MethodPost:
		var req struct {
			Zone    string `json:"zone"`
			Domain  string `json:"domain"`
			Type    string `json:"type"`
			TTL     int    `json:"ttl"`
			Answers []struct {
				Answer []any `json:"answer"`
			} `json:"answers"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		if req.Zone == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "missing \"zone\" in request JSON"})
			return
		}
		if req.Domain == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "missing \"domain\" in request JSON"})
			return
		}
		if req.Type == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "missing \"type\" in request JSON"})
			return
		}

		answers := make([][]string, 0, len(req.Answers))
		for _, a := range req.Answers {
			row := make([]string, 0, len(a.Answer))
			for _, v := range a.Answer {
				row = append(row, fmt.Sprint(v))
			}
			answers = append(answers, row)
		}

		s.mu.Lock()
		s.records[key] = mockRecordSet{Zone: zone, Domain: domain, Type: strings.ToUpper(rtype), TTL: req.TTL, Answers: answers}
		rs := s.records[key]
		s.mu.Unlock()

		_ = json.NewEncoder(w).Encode(toRecordResponse(rs))
	case http.MethodDelete:
		s.mu.Lock()
		_, ok := s.records[key]
		if ok {
			delete(s.records, key)
		}
		s.mu.Unlock()

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "record not found"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func toRecordResponse(rs mockRecordSet) map[string]any {
	answers := make([]map[string]any, 0, len(rs.Answers))
	for _, a := range rs.Answers {
		row := make([]any, 0, len(a))
		for _, v := range a {
			row = append(row, v)
		}
		answers = append(answers, map[string]any{"answer": row})
	}

	return map[string]any{
		"zone":    rs.Zone,
		"domain":  rs.Domain,
		"type":    rs.Type,
		"ttl":     rs.TTL,
		"answers": answers,
	}
}

func newProviderForServer(t *testing.T, serverURL string) *Provider {
	t.Helper()
	return &Provider{
		APIKey:   "test-api-key",
		Endpoint: serverURL + "/v1/",
		Timeout:  2 * time.Second,
	}
}

func TestAppendRecordsMergesAnswers(t *testing.T) {
	mock := newMockNS1Server(t, "test-api-key")
	mock.setRecord("example.com", "www.example.com", "A", 60, []string{"1.1.1.1"})

	srv := httptest.NewServer(http.HandlerFunc(mock.serveHTTP))
	defer srv.Close()

	p := newProviderForServer(t, srv.URL)

	created, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.RR{Name: "www", Type: "A", TTL: 120 * time.Second, Data: "2.2.2.2"},
		libdns.RR{Name: "www", Type: "A", TTL: 120 * time.Second, Data: "1.1.1.1"},
	})
	if err != nil {
		t.Fatalf("AppendRecords() error = %v", err)
	}
	if len(created) != 1 {
		t.Fatalf("AppendRecords() created = %d, want 1", len(created))
	}

	recs, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error = %v", err)
	}

	got := make([]string, 0, len(recs))
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Name == "www" && rr.Type == "A" {
			got = append(got, rr.Data)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Fatalf("A answers = %v, want [1.1.1.1 2.2.2.2]", got)
	}
}

func TestSetRecordsOverwritesRecordSet(t *testing.T) {
	mock := newMockNS1Server(t, "test-api-key")
	mock.setRecord("example.com", "www.example.com", "A", 60, []string{"1.1.1.1"}, []string{"2.2.2.2"})

	srv := httptest.NewServer(http.HandlerFunc(mock.serveHTTP))
	defer srv.Close()

	p := newProviderForServer(t, srv.URL)

	updated, err := p.SetRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.RR{Name: "www", Type: "A", TTL: 30 * time.Second, Data: "9.9.9.9"},
	})
	if err != nil {
		t.Fatalf("SetRecords() error = %v", err)
	}
	if len(updated) != 1 {
		t.Fatalf("SetRecords() updated = %d, want 1", len(updated))
	}

	recs, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error = %v", err)
	}

	got := make([]string, 0, len(recs))
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Name == "www" && rr.Type == "A" {
			got = append(got, rr.Data)
		}
	}
	if !slices.Equal(got, []string{"9.9.9.9"}) {
		t.Fatalf("A answers = %v, want [9.9.9.9]", got)
	}
}

func TestDeleteRecordsIgnoresMissing(t *testing.T) {
	mock := newMockNS1Server(t, "test-api-key")
	mock.setRecord("example.com", "www.example.com", "A", 60, []string{"1.1.1.1"}, []string{"2.2.2.2"})
	mock.setRecord("example.com", "example.com", "TXT", 300, []string{"hello"})

	srv := httptest.NewServer(http.HandlerFunc(mock.serveHTTP))
	defer srv.Close()

	p := newProviderForServer(t, srv.URL)

	deleted, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.RR{Name: "www", Type: "A", TTL: 60 * time.Second, Data: "2.2.2.2"},
		libdns.RR{Name: "www", Type: "A", TTL: 60 * time.Second, Data: "8.8.8.8"},
		libdns.RR{Name: "@", Type: "TXT", TTL: 300 * time.Second, Data: "hello"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords() error = %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("DeleteRecords() deleted = %d, want 2", len(deleted))
	}

	recs, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error = %v", err)
	}

	var gotA []string
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Name == "www" && rr.Type == "A" {
			gotA = append(gotA, rr.Data)
		}
		if rr.Type == "TXT" {
			t.Fatalf("TXT record should have been deleted, got %v", rr)
		}
	}
	if !slices.Equal(gotA, []string{"1.1.1.1"}) {
		t.Fatalf("remaining A records = %v, want [1.1.1.1]", gotA)
	}
}

func TestListZones(t *testing.T) {
	mock := newMockNS1Server(t, "test-api-key")

	srv := httptest.NewServer(http.HandlerFunc(mock.serveHTTP))
	defer srv.Close()

	p := newProviderForServer(t, srv.URL)
	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones() error = %v", err)
	}

	got := make([]string, 0, len(zones))
	for _, z := range zones {
		got = append(got, z.Name)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"example.com.", "example.net."}) {
		t.Fatalf("zones = %v, want [example.com. example.net.]", got)
	}
}

func TestDeleteRecordsDeletesCAA(t *testing.T) {
	mock := newMockNS1Server(t, "test-api-key")
	mock.setRecord("example.com", "test-delete-caa.example.com", "CAA", 300, []string{"0", "issue", "ca.example.com"})

	srv := httptest.NewServer(http.HandlerFunc(mock.serveHTTP))
	defer srv.Close()

	p := newProviderForServer(t, srv.URL)

	deleted, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.CAA{
			Name:  "test-delete-caa",
			TTL:   300 * time.Second,
			Flags: 0,
			Tag:   "issue",
			Value: "ca.example.com",
		},
	})
	if err != nil {
		t.Fatalf("DeleteRecords() error = %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("DeleteRecords() deleted = %d, want 1", len(deleted))
	}

	recs, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords() error = %v", err)
	}
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Name == "test-delete-caa" && rr.Type == "CAA" {
			t.Fatalf("CAA record should have been deleted, got %v", rr)
		}
	}
}
