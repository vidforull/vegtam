package cli

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core/output"
)

// validateJSON checks that doc, the stdout of a command, is one JSON
// document that output.Schema accepts.
func validateJSON(t *testing.T, doc string) {
	t.Helper()
	var schema, v map[string]any
	if err := json.Unmarshal([]byte(output.Schema), &schema); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("not one JSON object: %v\n%s", err, doc)
	}
	for _, err := range validate(schema, schema, v, "$") {
		t.Errorf("schema: %s\n%s", err, doc)
	}
}

// validate checks v against node, a part of the schema root. It knows
// exactly the keywords the schema uses and reports any other. Unlike the
// schema, it also rejects properties that node does not declare, so that
// output the schema has not caught up with fails here.
func validate(root, node map[string]any, v any, path string) []string {
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, path+": "+fmt.Sprintf(format, args...)) }
	for key, want := range node {
		switch key {
		case "$schema", "$defs", "title", "description", "properties":
		case "$ref":
			name, _ := strings.CutPrefix(must[string](want), "#/$defs/")
			def := must[map[string]any](must[map[string]any](root["$defs"])[name])
			errs = append(errs, validate(root, def, v, path)...)
		case "const":
			if !reflect.DeepEqual(v, want) {
				fail("%v, want %v", v, want)
			}
		case "type":
			ok := false
			switch want {
			case "object":
				_, ok = v.(map[string]any)
			case "array":
				_, ok = v.([]any)
			case "string":
				_, ok = v.(string)
			case "boolean":
				_, ok = v.(bool)
			case "number":
				_, ok = v.(float64)
			case "integer":
				f, isNum := v.(float64)
				ok = isNum && f == math.Trunc(f)
			}
			if !ok {
				fail("%v is not of type %s", v, want)
			}
		case "required":
			obj, _ := v.(map[string]any)
			for _, name := range must[[]any](want) {
				if _, ok := obj[must[string](name)]; !ok {
					fail("missing %s", name)
				}
			}
		case "items":
			arr, _ := v.([]any)
			for i, item := range arr {
				errs = append(errs, validate(root, must[map[string]any](want), item, fmt.Sprintf("%s[%d]", path, i))...)
			}
		default:
			fail("the validator does not know the keyword %s", key)
		}
	}
	if obj, ok := v.(map[string]any); ok && node["$ref"] == nil {
		props, _ := node["properties"].(map[string]any)
		for name, val := range obj {
			if p, ok := props[name]; ok {
				errs = append(errs, validate(root, must[map[string]any](p), val, path+"."+name)...)
			} else {
				fail("property %s is not in the schema", name)
			}
		}
	}
	return errs
}

func TestValidate(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal([]byte(output.Schema), &schema); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		`{}`:                                "missing schema_version",
		`{"schema_version": 2}`:             "2, want 1",
		`{"schema_version": 1, "extra": 1}`: "property extra is not in the schema",
		`{"schema_version": 1, "error": {"kind": "x"}}`:                     "$.error: missing message",
		`{"schema_version": 1, "results": [{"response": {"status": 1.5}}]}`: "$.results[0].response.status: 1.5 is not of type integer",
	}
	for doc, want := range bad {
		var v map[string]any
		decode(t, doc, &v)
		if errs := validate(schema, schema, v, "$"); !strings.Contains(strings.Join(errs, "\n"), want) {
			t.Errorf("validate(%s) = %q, want an error with %q", doc, errs, want)
		}
	}
}

// must returns v as a T. The schema is vegtam's own: anything else is a
// mistake in it.
func must[T any](v any) T {
	x, ok := v.(T)
	if !ok {
		panic(fmt.Sprintf("schema: %v is a %T, not a %T", v, v, x))
	}
	return x
}
