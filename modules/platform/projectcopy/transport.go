// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/harness/cli/v3/pkg/auth"
)

const secretsPath = "/ng/api/v2/secrets"
const responseLimit = 4 << 20

type Transport struct {
	auth *auth.ResolvedAuth
	http *http.Client
	wait func(context.Context, time.Duration) error
}

func NewTransport(a *auth.ResolvedAuth) *Transport {
	return &Transport{auth: a, http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, wait: wait}
}

func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return errors.New("secret inventory cancelled")
	}
}

// The POST below is a documented list operation, never a resource creation.
func (t *Transport) read(ctx context.Context, scope Scope, id string, page int, target any) error {
	base, err := url.Parse(t.auth.APIUrl)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("secret inventory requires a valid HTTPS API base URL without credentials, query or fragment")
	}
	method, path, body := http.MethodPost, secretsPath+"/list/secrets", `{"filterType":"Secret"}`
	if id != "" {
		if !ValidIdentifier(id) {
			return errors.New("invalid secret inventory identity")
		}
		method, path, body = http.MethodGet, secretsPath+"/"+id, ""
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	q := url.Values{"accountIdentifier": {scope.Account}, "orgIdentifier": {scope.Org}, "projectIdentifier": {scope.Source}}
	if id == "" {
		q.Set("pageIndex", strconv.Itoa(page))
		q.Set("pageSize", "100")
	}
	base.RawQuery = q.Encode()
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, base.String(), strings.NewReader(body))
		if err != nil {
			return errors.New("cannot prepare secret inventory request")
		}
		t.auth.SetAuthHeader(req)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		// Do not use the generic client: even its raw path logs URLs and network errors.
		resp, err := t.http.Do(req)
		if err != nil {
			if attempt == 2 || ctx.Err() != nil {
				return errors.New("secret inventory request failed")
			}
			if t.wait(ctx, time.Duration(attempt+1)*time.Second) != nil {
				return errors.New("secret inventory cancelled")
			}
			continue
		}
		retry := resp.StatusCode == 429 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504
		if retry && attempt < 2 {
			delay := time.Duration(attempt+1) * time.Second
			if raw := resp.Header.Get("Retry-After"); raw != "" {
				if seconds, e := strconv.Atoi(raw); e == nil && seconds >= 0 {
					delay = time.Duration(min(seconds, 11)) * time.Second
				} else if date, e := http.ParseTime(raw); e == nil {
					delay = max(time.Until(date), 0)
				} else {
					resp.Body.Close()
					return errors.New("secret inventory retry policy unavailable")
				}
			}
			resp.Body.Close()
			if delay > 10*time.Second {
				return errors.New("secret inventory rate limited; retry later")
			}
			if t.wait(ctx, delay) != nil {
				return errors.New("secret inventory cancelled")
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return errors.New("secret inventory read denied or unavailable")
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
		resp.Body.Close()
		if err != nil || len(data) > responseLimit {
			return errors.New("secret inventory response incomplete or too large")
		}
		dataObject := "unknown"
		switch target.(type) {
		case *envelope[pageData]:
			dataObject = "page"
		case *envelope[record]:
			dataObject = "record"
		}
		if err := jsonStructure(data, "envelope", dataObject); err != nil {
			return err
		}
		if err := json.Unmarshal(data, target); err != nil {
			return decodeError(err, "unknown", nil)
		}
		return nil
	}
	return errors.New("secret inventory retries exhausted")
}

type decodeFault struct {
	operation, reason, path, kind string
}

func (f *decodeFault) Error() string {
	return "malformed secret inventory response (operation=" + closedLabel(f.operation, "initial-list", "detail", "consistency-relist") +
		" reason=" + closedLabel(f.reason, "invalid-json", "duplicate-key", "canonical-alias", "canonical-null", "known-field-kind-mismatch", "object-kind-mismatch", "unsupported-pagination-control") +
		" path=" + diagnosticPath(f.path) + " kind=" + closedLabel(f.kind, "object", "array", "string", "number", "boolean", "null") + ")"
}

func closedLabel(value string, labels ...string) string {
	for _, label := range labels {
		if value == label {
			return label
		}
	}
	return "unknown"
}

func schemaFields(object string) []string {
	switch object {
	case "envelope":
		return []string{"status", "data"}
	case "page":
		return []string{"totalPages", "totalItems", "pageItemCount", "pageSize", "content", "pageIndex", "empty", "pageToken"}
	case "record":
		return []string{"secret", "updatedAt", "draft"}
	case "secret":
		return []string{"identifier", "name", "orgIdentifier", "projectIdentifier", "type", "spec"}
	}
	return nil
}

func fieldPath(object, key string) string {
	for _, field := range schemaFields(object) {
		if key == field {
			return closedLabel(object, "envelope", "page", "record", "secret") + "." + field
		}
	}
	return "unknown"
}

func diagnosticPath(path string) string {
	if object := closedLabel(path, "envelope", "page", "record", "secret"); object != "unknown" {
		return object
	}
	object, key, _ := strings.Cut(path, ".")
	return fieldPath(object, key)
}

func jsonKind(data []byte) string {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return "unknown"
	}
	switch data[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		if data[0] == '-' || (data[0] >= '0' && data[0] <= '9') {
			return "number"
		}
	}
	return "unknown"
}

// Parser error fields may contain payload; never format or retain the original error.
func decodeError(err error, object string, fields map[string]json.RawMessage) error {
	var fault *decodeFault
	if errors.As(err, &fault) {
		return fault
	}
	var mismatch *json.UnmarshalTypeError
	if errors.As(err, &mismatch) {
		if path := fieldPath(object, mismatch.Field); path != "unknown" {
			return &decodeFault{reason: "known-field-kind-mismatch", path: path, kind: jsonKind(fields[mismatch.Field])}
		}
	}
	return &decodeFault{}
}

func atOperation(err error, operation string) error {
	var fault *decodeFault
	if errors.As(err, &fault) {
		localized := *fault
		localized.operation = closedLabel(operation, "initial-list", "detail", "consistency-relist")
		return &localized
	}
	return err
}

func canonicalObject(data []byte, object string) (map[string]json.RawMessage, error) {
	if err := jsonStructure(data, object, "unknown"); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return nil, &decodeFault{reason: "object-kind-mismatch", path: object, kind: jsonKind(data)}
	}
	for _, control := range schemaFields(object) {
		for key := range fields {
			if key != control && strings.EqualFold(key, control) {
				return nil, &decodeFault{reason: "canonical-alias", path: fieldPath(object, control)}
			}
		}
		if string(fields[control]) == "null" {
			return nil, &decodeFault{reason: "canonical-null", path: fieldPath(object, control), kind: "null"}
		}
	}
	return fields, nil
}

func jsonStructure(data []byte, object, dataObject string) error {
	if !json.Valid(data) {
		return &decodeFault{reason: "invalid-json"}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var value func(string, string) error
	value = func(path, object string) error {
		token, err := dec.Token()
		if err != nil {
			return &decodeFault{}
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, e := dec.Token()
				if e != nil {
					return &decodeFault{}
				}
				s, ok := key.(string)
				if !ok {
					return &decodeFault{}
				}
				if seen[s] {
					return &decodeFault{reason: "duplicate-key", path: fieldPath(object, s)}
				}
				seen[s] = true
				child := "unknown"
				switch {
				case object == "envelope" && s == "data":
					child = dataObject
				case object == "record" && s == "secret":
					child = "secret"
				}
				if err := value(fieldPath(object, s), child); err != nil {
					return err
				}
			}
		case '[':
			child := "unknown"
			if path == "page.content" {
				child = "record"
			}
			for dec.More() {
				if err := value("unknown", child); err != nil {
					return err
				}
			}
		default:
			return &decodeFault{}
		}
		closing := json.Delim(']')
		if delim == '{' {
			closing = '}'
		}
		end, e := dec.Token()
		if e != nil || end != closing {
			return &decodeFault{}
		}
		return nil
	}
	if err := value(object, object); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return &decodeFault{}
	}
	return nil
}
