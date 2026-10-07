package main

// TEMPORARY DEBUGGING AID. Delete this file when you are done.
//
// With HYDROXIDE_TRACE=1, prints a redacted trace of the /auth* API calls to
// stderr: request headers that matter for login, the HTTP status, and the JSON
// response with secrets (SRP parameters, tokens) replaced by "<redacted>".
// Request bodies (which contain your SRP proof) are never printed.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

var hxTraceRedact = map[string]bool{
	"Modulus":                true,
	"ServerEphemeral":        true,
	"Salt":                   true,
	"SRPSession":             true,
	"ServerProof":            true,
	"AccessToken":            true,
	"RefreshToken":           true,
	"UID":                    true,
	"UserID":                 true,
	"HumanVerificationToken": true,
}

type hxTraceTransport struct {
	next http.RoundTripper
}

func (t hxTraceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	traced := strings.Contains(req.URL.Path, "/auth")
	if traced {
		hvToken := req.Header.Get("X-Pm-Human-Verification-Token")
		fmt.Fprintf(os.Stderr, "TRACE > %s %s\n", req.Method, req.URL.String())
		fmt.Fprintf(os.Stderr, "TRACE >   appversion=%q apiversion=%q user-agent=%q\n",
			req.Header.Get("X-Pm-Appversion"), req.Header.Get("X-Pm-Apiversion"), req.Header.Get("User-Agent"))
		fmt.Fprintf(os.Stderr, "TRACE >   human-verification: token-sent=%v (len %d) type=%q\n",
			hvToken != "", len(hvToken), req.Header.Get("X-Pm-Human-Verification-Token-Type"))
	}

	resp, err := t.next.RoundTrip(req)
	if !traced {
		return resp, err
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "TRACE < transport error: %v\n", err)
		return resp, err
	}

	body, readErr := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = ioutil.NopCloser(bytes.NewReader(body))
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "TRACE < %s (reading body failed: %v)\n", resp.Status, readErr)
		return resp, nil
	}
	fmt.Fprintf(os.Stderr, "TRACE < %s\n", resp.Status)
	fmt.Fprintf(os.Stderr, "TRACE <   %s\n", hxTraceRedactJSON(body))
	return resp, nil
}

func hxTraceRedactJSON(b []byte) string {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Sprintf("<not JSON, %d bytes>", len(b))
	}
	hxTraceRedactValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return "<unprintable>"
	}
	return string(out)
}

func hxTraceRedactValue(v interface{}) {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, val := range x {
			if hxTraceRedact[k] {
				x[k] = "<redacted>"
			} else {
				hxTraceRedactValue(val)
			}
		}
	case []interface{}:
		for _, e := range x {
			hxTraceRedactValue(e)
		}
	}
}

func init() {
	if os.Getenv("HYDROXIDE_TRACE") != "" {
		http.DefaultTransport = hxTraceTransport{http.DefaultTransport}
	}
}
