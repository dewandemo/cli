// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCopyAppliesCDCoreAndSkipsIdenticalRerun(t *testing.T) {
	api := newCopyAPI(false)
	report, err := Copy(context.Background(), api.transport(), testScope, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, strings.Join(api.seen, "\n"))
	}
	if !report.InventoryComplete || report.Readiness == "" {
		t.Fatalf("readiness %q", report.Readiness)
	}
	raw, _ := json.Marshal(report)
	for _, leaked := range []string{"SUPER_SECRET", "vault/path#key"} {
		if strings.Contains(string(raw), leaked) {
			t.Fatalf("report leaked %s", leaked)
		}
	}
	if !containsResult(report, "pipeline", "gitpipe", ActionSkipped) {
		t.Fatal("git-backed pipeline was not skipped")
	}
	if !containsResult(report, "reference", "account.shared_connector", ActionShared) {
		t.Fatal("account connector was copied instead of reported")
	}
	if len(report.DelegateSelectors) != 1 || !strings.Contains(report.DelegateSelectors[0].Reason, "harness-delegate") {
		t.Fatalf("delegate check %#v", report.DelegateSelectors)
	}
	var secretBody, triggerBody, projectBody string
	for _, call := range api.mutating {
		switch {
		case strings.Contains(call.body, "db_password"):
			secretBody = call.body
		case strings.Contains(call.path, "/triggers"):
			triggerBody = call.body
		case call.path == "/ng/api/projects":
			projectBody = call.body
		}
	}
	if !strings.Contains(secretBody, InlineSecretPlaceholder) || strings.Contains(secretBody, "SUPER_SECRET") {
		t.Fatalf("inline secret body = %s", secretBody)
	}
	if !strings.Contains(triggerBody, "enabled: false") {
		t.Fatalf("trigger body = %s", triggerBody)
	}
	if !strings.Contains(projectBody, `"identifier":"destination"`) || !strings.Contains(projectBody, `"name":"destination"`) || strings.Contains(projectBody, `"name":"Source"`) || !strings.Contains(projectBody, "CD") {
		t.Fatalf("project body = %s", projectBody)
	}
	for _, call := range api.mutating {
		if strings.Contains(call.path, "delegate") {
			t.Fatal("delegate was created")
		}
	}
	before := len(api.mutating)
	again, err := Copy(context.Background(), api.transport(), testScope, true)
	if err != nil {
		t.Fatalf("%v\n%s", err, strings.Join(api.seen, "\n"))
	}
	if len(api.mutating) != before {
		t.Fatalf("rerun wrote %d extra resources", len(api.mutating)-before)
	}
	if !containsResult(again, "secret", "db_password", ActionSkip) || !containsResult(again, "pipeline", "deploy", ActionSkip) {
		t.Fatal("identical rerun did not skip")
	}
}

func TestCopyPlanDoesNotWrite(t *testing.T) {
	api := newCopyAPI(false)
	report, err := Copy(context.Background(), api.transport(), testScope, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(api.mutating) != 0 {
		t.Fatalf("plan wrote %#v", api.mutating)
	}
	if !containsResult(report, "secret", "db_password", ActionCreate) || !strings.Contains(strings.Join(report.SecretsPendingValue, ","), "db_password") {
		t.Fatal("plan did not include the inline secret")
	}
}

func TestCopyConflictWritesNothing(t *testing.T) {
	api := newCopyAPI(true)
	report, err := Copy(context.Background(), api.transport(), testScope, true)
	if err == nil || !strings.Contains(err.Error(), "nothing written") && !strings.Contains(err.Error(), "differs") {
		t.Fatalf("err=%v", err)
	}
	if len(api.mutating) != 0 {
		t.Fatalf("conflict wrote %#v", api.mutating)
	}
	if !containsResult(report, "pipeline", "deploy", ActionConflict) {
		t.Fatal("conflict missing from report")
	}
}

func TestCopyAcceptsLiveInlineSecretSchema(t *testing.T) {
	s := &secret{Identifier: "github-pat", Name: "github-pat", Org: testScope.Org, Project: testScope.Source, Type: "SecretText", Spec: map[string]json.RawMessage{
		"secretManagerIdentifier": json.RawMessage(`"harnessSecretManager"`),
		"valueType":               json.RawMessage(`"Inline"`),
		"value":                   json.RawMessage(`null`),
		"additionalMetadata":      json.RawMessage(`null`),
	}}
	if classify(s).Capability != MappingRequired {
		t.Fatal(classify(s))
	}
}

func TestRewriteDisablesTriggersAndRewritesProject(t *testing.T) {
	doc, err := rewriteYAML("trigger:\n  identifier: push\n  enabled: true\n  pipelineIdentifier: deploy\n  projectIdentifier: source\n", testScope.Org, testScope.Destination, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc, "projectIdentifier: "+testScope.Destination) || !strings.Contains(doc, "enabled: false") || strings.Contains(doc, "projectIdentifier: source") {
		t.Fatal(doc)
	}
}

func containsResult(report Report, kind, id string, action Action) bool {
	for _, item := range report.Results {
		if item.Kind == kind && item.Identifier == id && item.Action == action {
			return true
		}
	}
	return false
}

type copyCall struct{ method, path, body, project string }

type copyAPI struct {
	conflict bool
	mutating []copyCall
	stored   map[string]string
	seen     []string
}

func newCopyAPI(conflict bool) *copyAPI {
	return &copyAPI{conflict: conflict, stored: map[string]string{}}
}

func (a *copyAPI) transport() *Transport {
	return fakeTransport(func(r *http.Request) (*http.Response, error) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		path := strings.TrimPrefix(r.URL.Path, "/gateway")
		project := r.URL.Query().Get("projectIdentifier")
		a.seen = append(a.seen, r.Method+" "+path+" project="+project)
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			if !strings.Contains(path, "/list") {
				call := copyCall{method: r.Method, path: path, body: string(body), project: project}
				a.mutating = append(a.mutating, call)
				a.stored[storeKey(call)] = string(body)
			}
		}
		return response(a.serve(r.Method, path, project, string(body))), nil
	})
}

func (a *copyAPI) serve(method, path, project, body string) (int, string) {
	switch {
	case path == "/ng/api/v2/secrets/list/secrets":
		if project != testScope.Source {
			return 200, emptySecretPage()
		}
		return 200, sourceSecrets()
	case strings.HasPrefix(path, "/ng/api/v2/secrets/") && method == http.MethodGet:
		return a.storedSecret(project, strings.TrimPrefix(path, "/ng/api/v2/secrets/"))
	case path == "/ng/api/projects/"+testScope.Source:
		return 200, `{"status":"SUCCESS","data":{"project":{"identifier":"source","name":"Source","orgIdentifier":"fixture_org","description":"demo","color":"#004fc4","modules":["CD"]}}}`
	case path == "/ng/api/projects/"+testScope.Destination && method == http.MethodGet:
		if _, ok := a.stored[http.MethodPost+" "+"/ng/api/projects"+" "+""]; ok || a.conflict {
			return 200, `{"status":"SUCCESS","data":{"project":{"identifier":"destination","name":"Source","orgIdentifier":"fixture_org"}}}`
		}
		return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
	case path == "/ng/api/connectors/listV2":
		if project != testScope.Source {
			return 200, emptyPage()
		}
		return 200, `{"status":"SUCCESS","data":{"content":[{"connector":{"identifier":"github","name":"github","type":"Github","orgIdentifier":"fixture_org","projectIdentifier":"source","spec":{"delegateSelectors":["cd-delegate"],"connectorRef":"account.shared_connector"}}}],"totalPages":1,"totalItems":1}}`
	case strings.HasPrefix(path, "/ng/api/connectors/") && method == http.MethodGet:
		return a.storedJSON(http.MethodPost+" /ng/api/connectors "+project, "connector")
	case path == "/ng/api/servicesV2" && method == http.MethodGet:
		return a.yamlList(project, "service", "svc", "service:\n  identifier: svc\n  name: svc\n  orgIdentifier: fixture_org\n  projectIdentifier: source\n")
	case strings.HasPrefix(path, "/ng/api/servicesV2/") && method == http.MethodGet:
		return a.storedYAML(http.MethodPost+" /ng/api/servicesV2 "+project, "service")
	case path == "/ng/api/environmentsV2" && method == http.MethodGet:
		return a.yamlList(project, "environment", "prod", "environment:\n  identifier: prod\n  name: prod\n  orgIdentifier: fixture_org\n  projectIdentifier: source\n")
	case strings.HasPrefix(path, "/ng/api/environmentsV2/") && path != "/ng/api/environmentsV2/serviceOverrides" && method == http.MethodGet:
		return a.storedYAML(http.MethodPost+" /ng/api/environmentsV2 "+project, "environment")
	case path == "/ng/api/infrastructures" || path == "/ng/api/environmentsV2/serviceOverrides":
		return 200, emptyPage()
	case path == "/template/api/templates/list":
		if project != testScope.Source {
			return 200, emptyPage()
		}
		return 200, `{"status":"SUCCESS","data":{"content":[{"identifier":"step","name":"step","versionLabel":"v1","stableTemplate":true,"storeType":"INLINE"}],"totalPages":1,"totalItems":1}}`
	case strings.HasPrefix(path, "/template/api/templates/") && method == http.MethodGet:
		return a.template(project)
	case path == "/pipeline/api/pipelines/list":
		if project != testScope.Source {
			return 200, emptyPage()
		}
		return 200, `{"status":"SUCCESS","data":{"content":[{"identifier":"deploy","name":"deploy","storeType":"INLINE"},{"identifier":"gitpipe","name":"gitpipe","storeType":"REMOTE"}],"totalPages":1,"totalItems":2}}`
	case path == "/pipeline/api/pipelines/deploy" && method == http.MethodGet:
		if project == testScope.Destination && a.conflict {
			return 200, `{"status":"SUCCESS","data":{"yamlPipeline":"pipeline:\n  identifier: deploy\n  name: other\n  orgIdentifier: fixture_org\n  projectIdentifier: destination\n"}}`
		}
		if project == testScope.Destination {
			if doc, ok := a.stored[http.MethodPost+" /pipeline/api/pipelines/v2 "+project]; ok {
				return 200, `{"status":"SUCCESS","data":{"yamlPipeline":` + jsonString(doc) + `}}`
			}
			return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
		}
		return 200, `{"status":"SUCCESS","data":{"yamlPipeline":"pipeline:\n  identifier: deploy\n  name: deploy\n  orgIdentifier: fixture_org\n  projectIdentifier: source\n"}}`
	case path == "/pipeline/api/inputSets" && method == http.MethodGet:
		return a.docList(project, "inputSet:\n  identifier: inputs\n  name: inputs\n  orgIdentifier: fixture_org\n  projectIdentifier: source\n  pipeline:\n    identifier: deploy\n", "inputs")
	case path == "/pipeline/api/inputSets/inputs" && method == http.MethodGet:
		return a.storedDoc(http.MethodPost+" /pipeline/api/inputSets "+project, "inputSetYaml")
	case path == "/pipeline/api/triggers" && method == http.MethodGet:
		return a.docList(project, "trigger:\n  identifier: push\n  name: push\n  enabled: true\n  pipelineIdentifier: deploy\n  orgIdentifier: fixture_org\n  projectIdentifier: source\n", "push")
	case path == "/pipeline/api/triggers/push" && method == http.MethodGet:
		return a.storedDoc(http.MethodPost+" /pipeline/api/triggers "+project, "yaml")
	case path == "/pm/api/v1/policies" && method == http.MethodGet:
		if project != testScope.Source {
			return 200, emptyPage()
		}
		return 200, `{"status":"SUCCESS","data":{"content":[{"identifier":"deny_prod","name":"deny","rego":"package pipeline","projectIdentifier":"source"}],"totalPages":1,"totalItems":1}}`
	case path == "/pm/api/v1/policies/deny_prod" && method == http.MethodGet:
		return a.storedGovernance(http.MethodPost + " /pm/api/v1/policies " + project)
	case path == "/pm/api/v1/policysets" && method == http.MethodGet:
		if project != testScope.Source {
			return 200, emptyPage()
		}
		return 200, `{"status":"SUCCESS","data":{"content":[{"identifier":"on_run","name":"on run","type":"pipeline","action":"onrun","enabled":true,"policies":[{"identifier":"deny_prod"}],"projectIdentifier":"source"}],"totalPages":1,"totalItems":1}}`
	case path == "/pm/api/v1/policysets/on_run" && method == http.MethodGet:
		return a.storedGovernance(http.MethodPost + " /pm/api/v1/policysets " + project)
	case path == "/ng/api/delegate-setup/listDelegates":
		return 200, `{"status":"SUCCESS","resource":[{"groupName":"harness-delegate","delegateGroupIdentifier":"del1","connectivityStatus":"connected","tags":["cd-delegate"]}],"totalPages":1}`
	case method == http.MethodPost || method == http.MethodPut:
		return 200, `{"status":"SUCCESS"}`
	default:
		return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
	}
}

func (a *copyAPI) storedSecret(project, id string) (int, string) {
	if project == testScope.Source && id == "db_password" {
		return 200, `{"status":"SUCCESS","data":{"secret":{"identifier":"db_password","name":"db","type":"SecretText","orgIdentifier":"fixture_org","projectIdentifier":"source","spec":{"type":"SecretText","valueType":"Inline","secretManagerIdentifier":"harnessSecretManager","value":"SUPER_SECRET"}},"updatedAt":17}}`
	}
	if project == testScope.Source && id == "ref_token" {
		return 200, `{"status":"SUCCESS","data":{"secret":{"identifier":"ref_token","name":"ref","type":"SecretText","orgIdentifier":"fixture_org","projectIdentifier":"source","spec":{"type":"SecretText","valueType":"Reference","secretManagerIdentifier":"org.manager","value":"vault/path#key"}},"updatedAt":17}}`
	}
	raw, ok := a.stored[http.MethodPost+" /ng/api/v2/secrets "+project+" "+id]
	if !ok {
		return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
	}
	var body map[string]any
	if json.Unmarshal([]byte(raw), &body) != nil {
		return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
	}
	data, _ := json.Marshal(map[string]any{"status": "SUCCESS", "data": body})
	return 200, string(data)
}

func sourceSecrets() string {
	return `{"status":"SUCCESS","data":{"totalPages":1,"totalItems":2,"pageItemCount":2,"pageSize":100,"content":[` +
		`{"secret":{"identifier":"db_password","name":"db","orgIdentifier":"fixture_org","projectIdentifier":"source","type":"SecretText","spec":{"type":"SecretText","valueType":"Inline","secretManagerIdentifier":"harnessSecretManager","value":"SUPER_SECRET"}},"updatedAt":17},` +
		`{"secret":{"identifier":"ref_token","name":"ref","orgIdentifier":"fixture_org","projectIdentifier":"source","type":"SecretText","spec":{"type":"SecretText","valueType":"Reference","secretManagerIdentifier":"org.manager","value":"vault/path#key"}},"updatedAt":18}` +
		`]}}`
}

func (a *copyAPI) yamlList(project, root, id, doc string) (int, string) {
	if project != testScope.Source {
		return 200, emptyPage()
	}
	return 200, `{"status":"SUCCESS","data":{"content":[{"` + root + `":{"identifier":"` + id + `","name":"` + id + `","orgIdentifier":"fixture_org","projectIdentifier":"source","yaml":` + jsonString(doc) + `}}],"totalPages":1,"totalItems":1}}`
}

func (a *copyAPI) storedYAML(key, root string) (int, string) {
	doc, ok := a.stored[key]
	if !ok {
		return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
	}
	return 200, `{"status":"SUCCESS","data":{"` + root + `":{"yaml":` + jsonString(doc) + `}}}`
}

func (a *copyAPI) storedJSON(key, root string) (int, string) {
	raw, ok := a.stored[key]
	if !ok {
		return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
	}
	var body map[string]any
	if json.Unmarshal([]byte(raw), &body) != nil {
		return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
	}
	entity, _ := body[root]
	data, _ := json.Marshal(map[string]any{"status": "SUCCESS", "data": map[string]any{root: entity}})
	return 200, string(data)
}

func (a *copyAPI) template(project string) (int, string) {
	if project == testScope.Source {
		return 200, `{"status":"SUCCESS","data":{"yaml":` + jsonString("template:\n  identifier: step\n  name: step\n  versionLabel: v1\n  type: Step\n  orgIdentifier: fixture_org\n  projectIdentifier: source\n  spec: {}\n") + `}}`
	}
	if doc, ok := a.stored[http.MethodPost+" /template/api/templates "+project]; ok {
		return 200, `{"status":"SUCCESS","data":{"yaml":` + jsonString(doc) + `}}`
	}
	return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
}

func (a *copyAPI) docList(project, doc, id string) (int, string) {
	if project != testScope.Source {
		return 200, emptyPage()
	}
	return 200, `{"status":"SUCCESS","data":{"content":[{"identifier":"` + id + `","name":"` + id + `","storeType":"INLINE","yaml":` + jsonString(doc) + `,"inputSetYaml":` + jsonString(doc) + `}],"totalPages":1,"totalItems":1}}`
}

func (a *copyAPI) storedDoc(key, field string) (int, string) {
	doc, ok := a.stored[key]
	if !ok {
		return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
	}
	data, _ := json.Marshal(map[string]any{"status": "SUCCESS", "data": map[string]any{field: doc, "yaml": doc}})
	return 200, string(data)
}

func (a *copyAPI) storedGovernance(key string) (int, string) {
	raw, ok := a.stored[key]
	if !ok {
		return 404, `{"status":"ERROR","code":"RESOURCE_NOT_FOUND"}`
	}
	return 200, `{"status":"SUCCESS","data":` + raw + `}`
}

func emptyPage() string {
	return `{"status":"SUCCESS","data":{"content":[],"totalPages":0,"totalItems":0}}`
}

func emptySecretPage() string {
	return `{"status":"SUCCESS","data":{"totalPages":0,"totalItems":0,"pageItemCount":0,"pageSize":100,"content":[]}}`
}

func storeKey(call copyCall) string {
	key := call.method + " " + call.path + " " + call.project
	if call.path == "/ng/api/v2/secrets" {
		var body map[string]any
		if json.Unmarshal([]byte(call.body), &body) == nil {
			if secret, ok := body["secret"].(map[string]any); ok {
				if id, ok := secret["identifier"].(string); ok {
					return key + " " + id
				}
			}
		}
	}
	return key
}

func jsonString(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}
