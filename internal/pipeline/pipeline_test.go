package pipeline

import (
	"strings"
	"testing"
)

func TestParseMultiline(t *testing.T) {
	raw := "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#HKG1\n" +
		"ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#USA1\n" +
		"vmess://eyJhZGQiOiIxLjEuMS4xIiwicG9ydCI6ODQ0MywiaWQiOiJhYWFhLWJiYmItY2NjYy1kZGRkIiwiYWlkIjoiMCIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lIiwicHMiOiJWTS0xIiwiVExTIjoiIn0="
	proxies := Parse(raw)
	if len(proxies) != 3 {
		t.Fatalf("expected 3 proxies, got %d", len(proxies))
	}
	if proxies[0].GetString("name") != "HKG1" {
		t.Errorf("proxy 0 name = %q", proxies[0].GetString("name"))
	}
	if proxies[1].GetString("name") != "USA1" {
		t.Errorf("proxy 1 name = %q", proxies[1].GetString("name"))
	}
	if proxies[2].Type() != "vmess" || proxies[2].GetString("name") != "VM-1" {
		t.Errorf("proxy 2 = %s %s", proxies[2].Type(), proxies[2].GetString("name"))
	}
}

func TestProcessToMihomo(t *testing.T) {
	raw := "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#HKG1"
	body, err := Process(Request{Raw: raw, Target: "mihomo"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"proxies:", "HKG1", "aes-256-gcm"} {
		if !strings.Contains(body, want) {
			t.Errorf("mihomo output missing %q", want)
		}
	}
}

func TestProcessToSurge(t *testing.T) {
	raw := "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#HKG1"
	body, err := Process(Request{Raw: raw, Target: "surge"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `HKG1=ss,1.2.3.4,8888,encrypt-method=aes-256-gcm,password="pass"`) {
		t.Errorf("surge output wrong: %s", body)
	}
}

func TestProcessToURI(t *testing.T) {
	raw := "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg4ODg=#HKG1"
	body, err := Process(Request{Raw: raw, Target: "uri"})
	if err != nil {
		t.Fatal(err)
	}
	// the uri target emits a plaintext URI list (one link per line),
	// mirroring the SINGLE-type URI_Producer in the original index.js
	if !strings.Contains(body, "ss://") || !strings.Contains(body, "HKG1") {
		t.Errorf("uri output wrong: %s", body)
	}
}
