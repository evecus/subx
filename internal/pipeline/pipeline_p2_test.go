package pipeline

import (
	"strings"
	"testing"
)

// Item 14: _subName / _subDisplayName are stamped on every proxy after
// parsing and before operators run (restful/sync.js:453-456).
func TestProcessTagsSubName(t *testing.T) {
	raw := "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#HKG1"
	body, err := Process(Request{
		Raw:            raw,
		Target:         "json",
		SubName:        "my-sub",
		SubDisplayName: "My Sub",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"_subName":"my-sub"`) {
		t.Errorf("output missing _subName: %s", body)
	}
	if !strings.Contains(body, `"_subDisplayName":"My Sub"`) {
		t.Errorf("output missing _subDisplayName: %s", body)
	}

	// no sub info → no tags
	plain, err := Process(Request{Raw: raw, Target: "json"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "_subName") {
		t.Errorf("output should not contain _subName without tagging: %s", plain)
	}
}
