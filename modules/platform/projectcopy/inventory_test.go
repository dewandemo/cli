// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/harness/cli/v3/pkg/auth"
	"github.com/harness/cli/v3/pkg/hlog"
)

const marker = "SYNTHETIC_SENSITIVE_MARKER"

var testScope = Scope{Account: "fixture_account", Org: "fixture_org", Source: "source", Destination: "destination"}

type roundTrip func(*http.Request) (*http.Response, error)

func (fn roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func fakeTransport(fn roundTrip) *Transport {
	t := NewTransport(&auth.ResolvedAuth{APIUrl: "https://inventory.invalid/gateway", AccountID: testScope.Account})
	t.http.Transport = fn
	t.wait = func(context.Context, time.Duration) error { return nil }
	return t
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

func fixture(id string) record {
	updated := int64(17)
	return record{Secret: &secret{Identifier: id, Name: marker, Org: testScope.Org, Project: testScope.Source, Type: "SecretText", Spec: map[string]json.RawMessage{"type": json.RawMessage(`"SecretText"`), "valueType": json.RawMessage(`"Reference"`), "secretManagerIdentifier": json.RawMessage(`"org.manager"`), "value": json.RawMessage(`"` + marker + `"`)}}, Updated: &updated}
}

func fixtureReader(count int, mutate func(int, *pageData)) readFn {
	records := make([]record, count)
	for i := range records {
		records[i] = fixture(fmt.Sprintf("secret_%03d", i))
	}
	return func(_ context.Context, _ Scope, id string, index int, target any) error {
		var value any
		if id != "" {
			for _, r := range records {
				if r.Secret.Identifier == id {
					value = map[string]any{"status": "SUCCESS", "data": r}
				}
			}
		} else {
			pages, total, size := (count+99)/100, count, 100
			start := min(index*100, count)
			end := min(start+100, count)
			n := end - start
			p := pageData{TotalPages: &pages, TotalItems: &total, PageSize: &size, PageItemCount: &n, Content: append([]record{}, records[start:end]...)}
			if mutate != nil {
				mutate(index, &p)
			}
			value = map[string]any{"status": "SUCCESS", "data": p}
		}
		data, _ := json.Marshal(value)
		return json.Unmarshal(data, target)
	}
}

func TestInventoryCompleteAndPayloadSafe(t *testing.T) {
	for _, count := range []int{0, 1, 100, 101, 201} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r, err := inventory(context.Background(), fixtureReader(count, nil), testScope)
			if err != nil || !r.InventoryComplete || r.ApplyAvailable || len(r.Secrets) != count {
				t.Fatalf("count=%d complete=%v err=%v", len(r.Secrets), r.InventoryComplete, err)
			}
			data, _ := json.Marshal(r)
			for _, s := range []string{marker, "org.manager", "secret_000", "valueType"} {
				if bytes.Contains(data, []byte(s)) {
					t.Fatal("unsafe API content in report")
				}
			}
			for _, item := range r.Secrets {
				if item.Capability != ReferenceOnly {
					t.Fatal("unexpected capability")
				}
			}
		})
	}
}

func TestInventoryRejectsIncompletePages(t *testing.T) {
	cases := map[string]func(int, *pageData){
		"missing total":   func(_ int, p *pageData) { p.TotalItems = nil },
		"missing content": func(_ int, p *pageData) { p.Content = nil },
		"missing pages":   func(_ int, p *pageData) { p.TotalPages = nil },
		"missing count":   func(_ int, p *pageData) { p.PageItemCount = nil },
		"truncated":       func(_ int, p *pageData) { p.Content = p.Content[:len(p.Content)-1] },
		"wrong scope":     func(_ int, p *pageData) { p.Content[0].Secret.Project = "other" },
		"wrong org":       func(_ int, p *pageData) { p.Content[0].Secret.Org = "other" },
		"duplicate":       func(_ int, p *pageData) { p.Content[1] = p.Content[0] },
		"changed total": func(i int, p *pageData) {
			if i > 0 {
				*p.TotalItems = 102
			}
		},
		"wrong page size":  func(_ int, p *pageData) { *p.PageSize = 50 },
		"draft":            func(_ int, p *pageData) { p.Content[0].Draft = true },
		"missing revision": func(_ int, p *pageData) { p.Content[0].Updated = nil },
		"wrong pages":      func(_ int, p *pageData) { *p.TotalPages = 9 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := inventory(context.Background(), fixtureReader(101, mutate), testScope)
			if err == nil || r.InventoryComplete {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
}

func TestCompletedInventoryStillFailsForRequiredMappings(t *testing.T) {
	for _, kind := range []string{"Inline", "Unknown"} {
		base := fixtureReader(1, nil)
		read := func(ctx context.Context, s Scope, id string, page int, target any) error {
			if id == "" {
				return base(ctx, s, id, page, target)
			}
			r := fixture(id)
			r.Secret.Spec["valueType"] = json.RawMessage(`"` + kind + `"`)
			data, _ := json.Marshal(map[string]any{"status": "SUCCESS", "data": r})
			return json.Unmarshal(data, target)
		}
		r, err := inventory(context.Background(), read, testScope)
		if err == nil || !r.InventoryComplete || r.ApplyAvailable || len(r.Secrets) != 1 {
			t.Fatal("unsupported plan appeared usable")
		}
	}
}

func TestInventoryDetailFailuresAndChurn(t *testing.T) {
	for _, mode := range []string{"denied", "missing", "scope", "identity", "type", "revision", "churn", "status"} {
		t.Run(mode, func(t *testing.T) {
			base := fixtureReader(1, nil)
			lists := 0
			read := func(ctx context.Context, s Scope, id string, page int, target any) error {
				if id == "" {
					lists++
					if lists == 2 && mode == "churn" {
						return fixtureReader(0, nil)(ctx, s, id, page, target)
					}
					return base(ctx, s, id, page, target)
				}
				if mode == "denied" {
					return errors.New("safe denied")
				}
				r := fixture(id)
				status := "SUCCESS"
				switch mode {
				case "missing":
					r.Secret = nil
				case "scope":
					r.Secret.Project = "other"
				case "identity":
					r.Secret.Identifier = "other"
				case "type":
					r.Secret.Type = "SecretFile"
				case "revision":
					*r.Updated++
				case "status":
					status = "FAILURE"
				}
				data, _ := json.Marshal(map[string]any{"status": status, "data": r})
				return json.Unmarshal(data, target)
			}
			r, err := inventory(context.Background(), read, testScope)
			if err == nil || r.InventoryComplete {
				t.Fatal("detail inconsistency accepted")
			}
		})
	}
}

func TestSecretCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*secret)
		want   Capability
	}{
		{"reference", func(*secret) {}, ReferenceOnly},
		{"inline", func(s *secret) { s.Spec["valueType"] = json.RawMessage(`"Inline"`); delete(s.Spec, "value") }, MappingRequired},
		{"unknown value type", func(s *secret) { s.Spec["valueType"] = json.RawMessage(`"Unknown"`) }, Blocked},
		{"unknown field", func(s *secret) { s.Spec["credentials"] = json.RawMessage(`"` + marker + `"`) }, Blocked},
		{"null value", func(s *secret) { s.Spec["value"] = json.RawMessage(`null`) }, Blocked},
		{"missing locator", func(s *secret) { delete(s.Spec, "value") }, Blocked},
		{"missing manager", func(s *secret) { delete(s.Spec, "secretManagerIdentifier") }, Blocked},
		{"mismatched spec", func(s *secret) { s.Spec["type"] = json.RawMessage(`"SSHKey"`) }, Blocked},
		{"unknown type", func(s *secret) { s.Type = marker }, Blocked},
		{"file", func(s *secret) { s.Type = "SecretFile"; s.Spec["type"] = json.RawMessage(`"SecretFile"`) }, Blocked},
		{"default manager", func(s *secret) { s.Spec["secretManagerIdentifier"] = json.RawMessage(`"harnessSecretManager"`) }, Blocked},
		{"scoped default manager", func(s *secret) { s.Spec["secretManagerIdentifier"] = json.RawMessage(`"account.harnessSecretManager"`) }, Blocked},
		{"dynamic manager", func(s *secret) { s.Spec["secretManagerIdentifier"] = json.RawMessage(`"<+input>"`) }, Blocked},
		{"dynamic locator", func(s *secret) { s.Spec["value"] = json.RawMessage(`"<+input>"`) }, Blocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fixture("sample").Secret
			tc.modify(s)
			got := classify(s)
			if got.Capability != tc.want {
				t.Fatalf("got %s want %s", got.Capability, tc.want)
			}
			data, _ := json.Marshal(got)
			if bytes.Contains(data, []byte(marker)) {
				t.Fatal("unsafe capability output")
			}
		})
	}
}

func TestTransportBoundsRetriesAndSanitizes(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "debug.log")
	hlog.SetDebugFile(logPath)
	for _, tc := range []struct {
		name      string
		statuses  []int
		body      string
		network   bool
		wantCalls int
		ok        bool
	}{
		{"success", []int{200}, `{"status":"SUCCESS"}`, false, 1, true},
		{"retry", []int{429, 503, 200}, `{"status":"SUCCESS"}`, false, 3, true},
		{"denied", []int{403}, marker, false, 1, false},
		{"unauthorized", []int{401}, marker, false, 1, false},
		{"server retries exhausted", []int{503, 503, 503}, marker, false, 3, false},
		{"network", nil, "", true, 3, false},
		{"malformed", []int{200}, `{"status":"` + marker, false, 1, false},
		{"duplicate keys", []int{200}, `{"status":"SUCCESS","status":"FAILURE"}`, false, 1, false},
		{"trailing document", []int{200}, `{} {}`, false, 1, false},
		{"too large", []int{200}, strings.Repeat("x", responseLimit+1), false, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			transport := fakeTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/sample") {
					t.Fatal("unexpected/mutating request")
				}
				if tc.network {
					return nil, errors.New(marker)
				}
				return response(tc.statuses[min(calls-1, len(tc.statuses)-1)], tc.body), nil
			})
			var target any
			err := transport.read(context.Background(), testScope, "sample", 0, &target)
			if (err == nil) != tc.ok || calls != tc.wantCalls {
				t.Fatalf("calls=%d error=%v", calls, err)
			}
			if err != nil && strings.Contains(err.Error(), marker) {
				t.Fatal("unsafe error")
			}
		})
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(marker)) {
		t.Fatal("debug payload leak")
	}
}

func TestTransportReadOnlyPaginationContract(t *testing.T) {
	reader := fixtureReader(101, nil)
	calls := 0
	tr := fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		q := r.URL.Query()
		if q.Get("projectIdentifier") != "source" || q.Get("orgIdentifier") != testScope.Org {
			t.Fatal("scope drift")
		}
		id := ""
		page := 0
		if r.URL.Path == "/gateway"+secretsPath+"/list/secrets" {
			if r.Method != "POST" {
				t.Fatal("unexpected method")
			}
			fmt.Sscan(q.Get("pageIndex"), &page)
		} else if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/gateway"+secretsPath+"/secret_") {
			id = strings.TrimPrefix(r.URL.Path, "/gateway"+secretsPath+"/")
		} else {
			t.Fatal("non-inventory request")
		}
		var target any
		if err := reader(r.Context(), testScope, id, page, &target); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(target)
		return response(200, string(data)), nil
	})
	report, err := Inventory(context.Background(), tr, testScope)
	if err != nil || !report.InventoryComplete || calls != 105 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestInventorySensitiveFailuresAcrossDiagnostics(t *testing.T) {
	for _, mode := range []string{"denied", "malformed", "network", "partial", "ambiguous", "null control", "pagination control", "unknown list schema"} {
		t.Run(mode, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "debug.log")
			hlog.SetDebugFile(logPath)
			tr := fakeTransport(func(r *http.Request) (*http.Response, error) {
				if mode == "network" {
					return nil, errors.New(marker)
				}
				if mode == "malformed" {
					return response(200, `{"message":"`+marker), nil
				}
				if mode != "denied" && r.Method == "POST" {
					var data any
					if err := fixtureReader(1, nil)(r.Context(), testScope, "", 0, &data); err != nil {
						t.Fatal(err)
					}
					b, _ := json.Marshal(data)
					body := string(b)
					switch mode {
					case "ambiguous":
						body = strings.Replace(body, `"draft":false`, `"draft":true,"Draft":false`, 1)
					case "null control":
						body = strings.Replace(body, `"draft":false`, `"draft":null`, 1)
					case "pagination control":
						body = strings.Replace(body, `"pageSize":100`, `"pageSize":100,"pageIndex":"`+marker+`"`, 1)
					case "unknown list schema":
						body = strings.Replace(body, `"spec":`, `"unprovenControl":"`+marker+`","spec":`, 1)
					}
					return response(200, body), nil
				}
				return response(403, `{"message":"`+marker+`","definition":"`+marker+`"}`), nil
			})
			outRead, outWrite, _ := os.Pipe()
			errRead, errWrite, _ := os.Pipe()
			oldOut, oldErr := os.Stdout, os.Stderr
			os.Stdout, os.Stderr = outWrite, errWrite
			defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
			r, err := Inventory(context.Background(), tr, testScope)
			json.NewEncoder(os.Stdout).Encode(r)
			fmt.Fprintln(os.Stderr, err)
			outWrite.Close()
			errWrite.Close()
			stdout, _ := io.ReadAll(outRead)
			stderr, _ := io.ReadAll(errRead)
			outRead.Close()
			errRead.Close()
			debug, _ := os.ReadFile(logPath)
			if err == nil || r.InventoryComplete {
				t.Fatal("failed inventory claimed complete")
			}
			for _, surface := range [][]byte{stdout, stderr, debug} {
				if bytes.Contains(surface, []byte(marker)) {
					t.Fatal("sensitive marker in diagnostics")
				}
			}
		})
	}
}

func TestUnknownSecretRootFieldsBlock(t *testing.T) {
	var s secret
	if err := json.Unmarshal([]byte(`{"type":"SecretText","privateSecret":true}`), &s); err != nil {
		t.Fatal(err)
	}
	if !s.Unproven || classify(&s).Capability != Blocked {
		t.Fatal("unknown root field accepted")
	}
}

func rewriteReader(base readFn, rewrite func(string, int, []byte) []byte) readFn {
	return func(ctx context.Context, s Scope, id string, page int, target any) error {
		var value any
		if err := base(ctx, s, id, page, &value); err != nil {
			return err
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return json.Unmarshal(rewrite(id, page, data), target)
	}
}

func TestInventoryRejectsAmbiguousControls(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"status aliases", `"status":"SUCCESS"`, `"status":"ERROR","Status":"SUCCESS"`},
		{"status aliases reversed", `"status":"SUCCESS"`, `"Status":"SUCCESS","status":"ERROR"`},
		{"status alias only", `"status":"SUCCESS"`, `"Status":"SUCCESS"`},
		{"null status", `"status":"SUCCESS"`, `"status":null`},
		{"draft aliases", `"draft":false`, `"draft":true,"Draft":false`},
		{"draft aliases reversed", `"draft":false`, `"Draft":false,"draft":true`},
		{"draft alias only", `"draft":false`, `"Draft":false`},
		{"null draft", `"draft":false`, `"draft":null`},
		{"string draft", `"draft":false`, `"draft":"false"`},
		{"data aliases", `"data":`, `"Data":null,"data":`},
		{"revision aliases", `"updatedAt":17`, `"updatedAt":-1,"UpdatedAt":17`},
		{"scope aliases", `"projectIdentifier":"source"`, `"projectIdentifier":"other","ProjectIdentifier":"source"`},
	} {
		for _, detail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/detail=%v", tc.name, detail), func(t *testing.T) {
				calls := 0
				read := rewriteReader(fixtureReader(1, nil), func(id string, _ int, data []byte) []byte {
					calls++
					if (id != "") == detail {
						return []byte(strings.Replace(string(data), tc.from, tc.to, 1))
					}
					return data
				})
				r, err := inventory(context.Background(), read, testScope)
				wantCalls := 1
				if detail {
					wantCalls = 2
				}
				if err == nil || r.InventoryComplete || len(r.Secrets) != 0 || calls != wantCalls {
					t.Fatalf("ambiguous controls accepted: calls=%d complete=%v err=%v", calls, r.InventoryComplete, err)
				}
			})
		}
	}
}

func TestInventoryValidatesOptionalPaginationControls(t *testing.T) {
	for _, control := range []string{
		`"pageIndex":99`, `"pageIndex":null`, `"pageIndex":"0"`, `"PageIndex":0`,
		`"empty":true`, `"empty":null`, `"empty":0`,
		`"pageToken":{}`, `"pageToken":null`, `"pageToken":"unproven_continuation"`,
		`"nextCursor":"unproven_continuation"`,
	} {
		t.Run(control, func(t *testing.T) {
			read := rewriteReader(fixtureReader(1, nil), func(id string, _ int, data []byte) []byte {
				if id == "" {
					return []byte(strings.Replace(string(data), `"pageSize":100`, `"pageSize":100,`+control, 1))
				}
				return data
			})
			r, err := inventory(context.Background(), read, testScope)
			if err == nil || r.InventoryComplete {
				t.Fatal("unproven pagination accepted")
			}
		})
	}
	for _, tc := range []struct {
		name  string
		count int
	}{
		{"wrong later page", 101}, {"false empty page", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := fixtureReader(tc.count, func(_ int, p *pageData) {
				zero, empty := 0, false
				p.PageIndex, p.Empty = &zero, &empty
			})
			r, err := inventory(context.Background(), read, testScope)
			if err == nil || r.InventoryComplete {
				t.Fatal("inconsistent page controls accepted")
			}
		})
	}
}

func TestInventoryPreservesDocumentedPaginationAndOptionalDraft(t *testing.T) {
	for _, tc := range []struct {
		count      int
		legacyZero bool
	}{
		{0, false}, {0, true}, {201, false},
	} {
		t.Run(fmt.Sprintf("count=%d/legacyZero=%v", tc.count, tc.legacyZero), func(t *testing.T) {
			base := fixtureReader(tc.count, func(index int, p *pageData) {
				empty, token := len(p.Content) == 0, ""
				p.PageIndex, p.Empty, p.PageToken = &index, &empty, &token
				if tc.legacyZero {
					*p.TotalPages = 1
				}
			})
			read := rewriteReader(base, func(_ string, _ int, data []byte) []byte {
				body := strings.ReplaceAll(string(data), `"draft":false,`, "")
				return []byte(strings.ReplaceAll(body, `"name":`, `"tags":{"Owner":"one","owner":"two"},"name":`))
			})
			r, err := inventory(context.Background(), read, testScope)
			if err != nil || !r.InventoryComplete || len(r.Secrets) != tc.count {
				t.Fatalf("documented pagination rejected: complete=%v err=%v", r.InventoryComplete, err)
			}
		})
	}
}

func TestInventoryDoesNotEraseUnknownListSchema(t *testing.T) {
	for _, tc := range []struct {
		name   string
		count  int
		page   int
		relist bool
	}{
		{"first page", 1, 0, false}, {"later page", 101, 1, false}, {"relist", 1, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lists := 0
			read := rewriteReader(fixtureReader(tc.count, nil), func(id string, page int, data []byte) []byte {
				if id == "" {
					lists++
					isRelist := lists > (tc.count+99)/100
					if page == tc.page && isRelist == tc.relist {
						return []byte(strings.Replace(string(data), `"spec":`, `"unprovenControl":true,"spec":`, 1))
					}
				}
				return data
			})
			r, err := inventory(context.Background(), read, testScope)
			if err == nil || r.InventoryComplete {
				t.Fatal("unknown list schema erased by minimal detail")
			}
		})
	}
}

func TestDecodeFaultOperationStages(t *testing.T) {
	for i, operation := range []string{"initial-list", "detail", "consistency-relist"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			tr := fakeTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == i+1 {
					return response(200, `{"status":null,"message":"`+marker+`"}`), nil
				}
				id := ""
				if r.Method == http.MethodGet {
					id = "secret_000"
				}
				var value any
				if err := fixtureReader(1, nil)(r.Context(), testScope, id, 0, &value); err != nil {
					t.Fatal(err)
				}
				data, _ := json.Marshal(value)
				return response(200, string(data)), nil
			})
			r, err := Inventory(context.Background(), tr, testScope)
			want := "malformed secret inventory response (operation=" + operation + " reason=canonical-null path=envelope.status kind=null)"
			if err == nil || err.Error() != want || calls != i+1 || r.InventoryComplete || r.ApplyAvailable {
				t.Fatalf("calls=%d complete=%v error=%v", calls, r.InventoryComplete, err)
			}
			observations := 0
			if i == 2 {
				observations = 1
			}
			data, _ := json.Marshal(r)
			if len(r.Secrets) != observations || bytes.Contains(data, []byte(marker)) {
				t.Fatal("failed read changed partial safe observations")
			}
		})
	}
}

func TestDecodeFaultReasonsAndCanonicalPaths(t *testing.T) {
	var value any
	if err := fixtureReader(1, nil)(context.Background(), testScope, "", 0, &value); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(value)
	base := string(data)
	patch := func(from, to string) string {
		t.Helper()
		if !strings.Contains(base, from) {
			t.Fatal("missing fixture replacement")
		}
		return strings.Replace(base, from, to, 1)
	}
	logPath := filepath.Join(t.TempDir(), "diagnostics.log")
	hlog.SetDebugFile(logPath)
	const authMarker = "SYNTHETIC_AUTH_DIAGNOSTIC_MARKER"
	for _, tc := range []struct {
		name, body, reason, path, kind string
		detail                         bool
	}{
		{"invalid JSON", `{"message":"` + marker, "invalid-json", "unknown", "unknown", false},
		{"known duplicate", patch(`"status":"SUCCESS"`, `"status":"SUCCESS","status":"`+marker+`"`), "duplicate-key", "envelope.status", "unknown", false},
		{"unknown duplicate", `{"` + marker + `":0,"` + marker + `":"` + authMarker + `"}`, "duplicate-key", "unknown", "unknown", false},
		{"nested unknown duplicate", `{"` + marker + `":{"status":0,"status":1}}`, "duplicate-key", "unknown", "unknown", false},
		{"record duplicate", patch(`"updatedAt":17`, `"updatedAt":17,"updatedAt":0`), "duplicate-key", "record.updatedAt", "unknown", false},
		{"secret duplicate", patch(`"identifier":"secret_000"`, `"identifier":"secret_000","identifier":"`+marker+`"`), "duplicate-key", "secret.identifier", "unknown", false},
		{"status alias", patch(`"status":"SUCCESS"`, `"Status":"`+marker+`"`), "canonical-alias", "envelope.status", "unknown", false},
		{"page alias", patch(`"pageSize":100`, `"PageSize":100`), "canonical-alias", "page.pageSize", "unknown", false},
		{"record alias", patch(`"draft":false`, `"DRAFT":false`), "canonical-alias", "record.draft", "unknown", false},
		{"secret alias", patch(`"identifier":`, `"Identifier":`), "canonical-alias", "secret.identifier", "unknown", false},
		{"null status", patch(`"status":"SUCCESS"`, `"status":null`), "canonical-null", "envelope.status", "null", false},
		{"null page", patch(`"pageSize":100`, `"pageSize":null`), "canonical-null", "page.pageSize", "null", false},
		{"null record", patch(`"draft":false`, `"draft":null`), "canonical-null", "record.draft", "null", false},
		{"status array", patch(`"status":"SUCCESS"`, `"status":[]`), "known-field-kind-mismatch", "envelope.status", "array", false},
		{"page string", patch(`"pageSize":100`, `"pageSize":"`+marker+`"`), "known-field-kind-mismatch", "page.pageSize", "string", false},
		{"page boolean", patch(`"pageSize":100`, `"pageSize":false`), "known-field-kind-mismatch", "page.pageSize", "boolean", false},
		{"revision string", patch(`"updatedAt":17`, `"updatedAt":"`+marker+`"`), "known-field-kind-mismatch", "record.updatedAt", "string", false},
		{"revision fractional number", patch(`"updatedAt":17`, `"updatedAt":1.5`), "known-field-kind-mismatch", "record.updatedAt", "number", false},
		{"secret identifier object", patch(`"identifier":"secret_000"`, `"identifier":{"`+marker+`":true}`), "known-field-kind-mismatch", "secret.identifier", "object", false},
		{"envelope array", `[]`, "object-kind-mismatch", "envelope", "array", false},
		{"page array", `{"status":"SUCCESS","data":[]}`, "object-kind-mismatch", "page", "array", false},
		{"record array", `{"status":"SUCCESS","data":[]}`, "object-kind-mismatch", "record", "array", true},
		{"secret array", `{"status":"SUCCESS","data":{"secret":[]}}`, "object-kind-mismatch", "secret", "array", true},
		{"unknown page control", patch(`"pageSize":100`, `"pageSize":100,"`+marker+`":"`+authMarker+`"`), "unsupported-pagination-control", "unknown", "unknown", false},
		{"token decoder overflow", `{"` + marker + `":1e1000}`, "unknown", "unknown", "unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			tr := fakeTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("x-api-key") != authMarker {
					t.Fatal("synthetic authentication not exercised")
				}
				return response(200, tc.body), nil
			})
			tr.auth.PATToken = authMarker
			tr.auth.APIUrl = "https://diagnostic.invalid/" + marker
			var target any = &envelope[pageData]{}
			if tc.detail {
				target = &envelope[record]{}
			}
			err := tr.read(context.Background(), testScope, "", 0, target)
			want := "malformed secret inventory response (operation=unknown reason=" + tc.reason + " path=" + tc.path + " kind=" + tc.kind + ")"
			if err == nil || err.Error() != want || calls != 1 {
				t.Fatalf("calls=%d error=%v; want %s", calls, err, want)
			}
		})
	}
	debug, err := os.ReadFile(logPath)
	if err != nil || bytes.Contains(debug, []byte(marker)) || bytes.Contains(debug, []byte(authMarker)) {
		t.Fatal("unsafe debug diagnostics")
	}
}

func TestDecodeFaultUnknownErrorsAndLabelsAreClosed(t *testing.T) {
	for _, err := range []error{
		errors.New(marker),
		fmt.Errorf("%s: %w", marker, &json.UnmarshalTypeError{Field: marker, Value: marker, Type: reflect.TypeFor[string]()}),
		&decodeFault{operation: marker, reason: marker, path: marker, kind: marker},
		&decodeFault{path: "page." + marker},
	} {
		got := atOperation(decodeError(err, "page", nil), marker)
		want := "malformed secret inventory response (operation=unknown reason=unknown path=unknown kind=unknown)"
		if got.Error() != want {
			t.Fatalf("unrecognized error escaped: %v", got)
		}
	}
	underlying := &json.UnmarshalTypeError{Field: "pageSize", Value: marker, Type: reflect.TypeFor[int]()}
	err := decodeError(fmt.Errorf("%s: %w", marker, underlying), "page", map[string]json.RawMessage{"pageSize": json.RawMessage(`"` + marker + `"`)})
	if err.Error() != "malformed secret inventory response (operation=unknown reason=known-field-kind-mismatch path=page.pageSize kind=string)" {
		t.Fatalf("raw typed error influenced diagnostics: %v", err)
	}
}

func TestTransportRetryAfterAndCancellation(t *testing.T) {
	for _, delay := range []string{"2", "999999999", "invalid"} {
		t.Run(delay, func(t *testing.T) {
			calls, waits := 0, 0
			tr := fakeTransport(func(*http.Request) (*http.Response, error) {
				calls++
				r := response(429, marker)
				r.Header.Set("Retry-After", delay)
				return r, nil
			})
			tr.wait = func(context.Context, time.Duration) error { waits++; return errors.New(marker) }
			var v any
			err := tr.read(context.Background(), testScope, "sample", 0, &v)
			if err == nil || calls != 1 || strings.Contains(err.Error(), marker) {
				t.Fatal("unsafe retry")
			}
			if delay == "2" && waits != 1 {
				t.Fatal("retry-after not honored")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if wait(ctx, time.Hour) == nil {
		t.Fatal("cancel ignored")
	}
}
