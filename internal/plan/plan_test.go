package plan

import (
	"reflect"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) *Plan {
	t.Helper()
	p, err := Decode(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecodeRejectsNonPlans(t *testing.T) {
	for name, in := range map[string]string{
		"not json":       "nope",
		"state document": `{"values": {}}`,
		"future format":  `{"format_version": "2.0"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(in)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestActions(t *testing.T) {
	cases := map[string]Action{
		`["create"]`:          Create,
		`["update"]`:          Update,
		`["delete"]`:          Delete,
		`["delete","create"]`: Replace,
		`["create","delete"]`: Replace,
		`["no-op"]`:           NoOp,
		`["read"]`:            Read,
		`["forget"]`:          Forget,
	}
	for actions, want := range cases {
		p := decode(t, `{"format_version":"1.2","resource_changes":[{"address":"a.b","change":{"actions":`+actions+`}}]}`)
		rc := p.ResourceChanges[0]
		if got := rc.Action(); got != want {
			t.Errorf("%s: got %s want %s", actions, got, want)
		}
		if cbd := rc.CreateBeforeDestroy(); cbd != (actions == `["create","delete"]`) {
			t.Errorf("%s: CreateBeforeDestroy = %v", actions, cbd)
		}
	}
}

func TestChangedAttributes(t *testing.T) {
	p := decode(t, `{"format_version":"1.2","resource_changes":[{"address":"x.y","change":{
		"actions":["update"],
		"before":{"a":1,"b":"same","c":["x"],"gone":true},
		"after":{"a":2,"b":"same","c":["x"],"new":null},
		"after_unknown":{"arn":true,"c":[false]}
	}}]}`)
	got := p.ResourceChanges[0].ChangedAttributes()
	want := []string{"a", "arn", "gone"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestChangedAttributesNilSides(t *testing.T) {
	p := decode(t, `{"format_version":"1.2","resource_changes":[{"address":"x.y","change":{"actions":["create"],"before":null,"after":{"a":1}}}]}`)
	if got := p.ResourceChanges[0].ChangedAttributes(); got != nil {
		t.Fatalf("create should report no changed attributes, got %v", got)
	}
}

func TestReplacePaths(t *testing.T) {
	p := decode(t, `{"format_version":"1.2","resource_changes":[{"address":"x.y","change":{
		"actions":["delete","create"],
		"replace_paths":[["settings",0,"tier"],["region"],["region"]]
	}}]}`)
	got := p.ResourceChanges[0].ReplacePaths()
	want := []string{"region", "settings.0.tier"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestSensitive(t *testing.T) {
	p := decode(t, `{"format_version":"1.2","resource_changes":[
		{"address":"a.a","change":{"actions":["update"],"before_sensitive":{"password":true},"after_sensitive":{}}},
		{"address":"b.b","change":{"actions":["update"],"before_sensitive":false,"after_sensitive":{"settings":[{"secret":true}]}}},
		{"address":"c.c","change":{"actions":["update"],"before_sensitive":true}}
	]}`)
	rcs := p.ResourceChanges
	if !rcs[0].Sensitive("password") || rcs[0].Sensitive("name") {
		t.Error("top-level mask")
	}
	if !rcs[1].Sensitive("settings") || rcs[1].Sensitive("name") {
		t.Error("nested mask should mark the whole attribute")
	}
	if !rcs[2].Sensitive("anything") {
		t.Error("whole-object mask")
	}
}

func TestMovedAndImported(t *testing.T) {
	p := decode(t, `{"format_version":"1.2","resource_changes":[
		{"address":"a.new","previous_address":"a.old","change":{"actions":["no-op"]}},
		{"address":"a.imp","change":{"actions":["no-op"],"importing":{"id":"i-123"}}}
	]}`)
	if !p.ResourceChanges[0].Moved() || p.ResourceChanges[0].Imported() {
		t.Error("move")
	}
	if !p.ResourceChanges[1].Imported() {
		t.Error("import")
	}
}

func TestLoadFixtures(t *testing.T) {
	for _, name := range []string{"aws", "gcp", "azure", "local"} {
		p, err := Load("../../testdata/plans/" + name + ".json")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(p.ResourceChanges) == 0 {
			t.Fatalf("%s: no resource changes", name)
		}
	}
}
