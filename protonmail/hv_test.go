package protonmail

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const hvResponse = `{
	"Code": 9001,
	"Error": "For security reasons, please complete CAPTCHA.",
	"Details": {
		"HumanVerificationMethods": ["captcha", "email"],
		"HumanVerificationToken": "tok123",
		"Title": "Human verification"
	}
}`

func newTestClient(srv *httptest.Server) *Client {
	return &Client{RootURL: srv.URL, AppVersion: "Other"}
}

func TestHumanVerificationErrorParsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(hvResponse))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	req, _ := c.newJSONRequest(http.MethodPost, "/auth", struct{}{})
	err := c.doJSON(req, new(authResp))

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T (%v)", err, err)
	}
	if apiErr.Code != ErrCodeHumanVerificationRequired {
		t.Errorf("unexpected code %v", apiErr.Code)
	}
	hv := apiErr.HumanVerification()
	if hv == nil {
		t.Fatal("expected human verification details")
	}
	if hv.Token != "tok123" || len(hv.Methods) != 2 {
		t.Errorf("unexpected details: %+v", hv)
	}
	if want := "https://verify.proton.me/?methods=captcha,email&token=tok123"; hv.URL() != want {
		t.Errorf("URL = %q, want %q", hv.URL(), want)
	}
}

func TestOtherErrorsHaveNoHumanVerification(t *testing.T) {
	err := &APIError{Code: 8002, Message: "Incorrect login credentials"}
	if err.HumanVerification() != nil {
		t.Error("unexpected human verification details")
	}
	// 9001 without a usable token must not be treated as solvable
	err = &APIError{Code: 9001, Message: "x", Details: []byte(`{}`)}
	if err.HumanVerification() != nil {
		t.Error("unexpected human verification details for empty token")
	}
}

func TestSuccessWithDetailsIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Code": 1000, "Details": {"foo": "bar"}}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	req, _ := c.newJSONRequest(http.MethodPost, "/anything", struct{}{})
	if err := c.doJSON(req, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHumanVerificationHeaders(t *testing.T) {
	var gotToken, gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Pm-Human-Verification-Token")
		gotType = r.Header.Get("X-Pm-Human-Verification-Token-Type")
		w.Write([]byte(`{"Code": 1000}`))
	}))
	defer srv.Close()
	c := newTestClient(srv)

	// Not set: no headers
	req, _ := c.newJSONRequest(http.MethodPost, "/auth", struct{}{})
	c.setHumanVerification(req)
	if err := c.doJSON(req, nil); err != nil {
		t.Fatal(err)
	}
	if gotToken != "" || gotType != "" {
		t.Errorf("unexpected headers: %q %q", gotToken, gotType)
	}

	// Set: headers are sent
	c.HumanVerification = &HumanVerification{Methods: []string{"captcha", "email"}, Token: "tok123"}
	req, _ = c.newJSONRequest(http.MethodPost, "/auth", struct{}{})
	c.setHumanVerification(req)
	if err := c.doJSON(req, nil); err != nil {
		t.Fatal(err)
	}
	if gotToken != "tok123" || gotType != "captcha,email" {
		t.Errorf("headers = %q, %q", gotToken, gotType)
	}
}
