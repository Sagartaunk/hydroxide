// Package protonmail implements a ProtonMail API client.
package protonmail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"log"
)

const Version = 3

const headerAPIVersion = "X-Pm-Apiversion"

type resp struct {
	Code int
	*RawAPIError

	// Details is only populated by the API on some errors (e.g. when human
	// verification is required). It lives here rather than in RawAPIError so
	// that a successful response carrying a "Details" key is not mistaken for
	// an error.
	Details json.RawMessage `json:"Details,omitempty"`
}

func (r *resp) Err() error {
	if err := r.RawAPIError; err != nil {
		return &APIError{
			Code:    r.Code,
			Message: err.Message,
			Details: r.Details,
		}
	}
	return nil
}

type maybeError interface {
	Err() error
}

type RawAPIError struct {
	Message string `json:"Error"`
}

type APIError struct {
	Code    int
	Message string

	// Details holds the raw, endpoint-specific error details, if any.
	Details json.RawMessage
}

func (err *APIError) Error() string {
	return fmt.Sprintf("[%v] %v", err.Code, err.Message)
}

// ErrCodeHumanVerificationRequired is the API error code returned when the
// server wants the client to complete a human verification challenge (usually
// a CAPTCHA) before it will accept the request.
const ErrCodeHumanVerificationRequired = 9001

// HumanVerification describes a human verification challenge. It is both what
// the server asks for (see APIError.HumanVerification) and what the client
// sends back, once the challenge has been completed in a browser, via
// Client.HumanVerification.
type HumanVerification struct {
	Methods []string `json:"HumanVerificationMethods"`
	Token   string   `json:"HumanVerificationToken"`
}

// URL returns the page on which the user can complete the challenge.
func (hv *HumanVerification) URL() string {
	return fmt.Sprintf("https://verify.proton.me/?methods=%v&token=%v",
		strings.Join(hv.Methods, ","), hv.Token)
}

// HumanVerification returns the verification challenge attached to the error,
// or nil if the error is not a (well-formed) human verification request.
func (err *APIError) HumanVerification() *HumanVerification {
	if err.Code != ErrCodeHumanVerificationRequired || len(err.Details) == 0 {
		return nil
	}
	hv := new(HumanVerification)
	if json.Unmarshal(err.Details, hv) != nil || hv.Token == "" {
		return nil
	}
	return hv
}

type Timestamp int64

func (t Timestamp) Time() time.Time {
	return time.Unix(int64(t), 0)
}

// Client is a ProtonMail API client.
type Client struct {
	RootURL    string
	AppVersion string
	Debug      bool

	HTTPClient *http.Client
	ReAuth     func() error

	// HumanVerification, if set, is sent along with authentication requests.
	// Set it to the challenge returned by a previous failed attempt (see
	// APIError.HumanVerification) once the user has completed it in a browser.
	HumanVerification *HumanVerification

	uid         string
	accessToken string
	keyRing     openpgp.EntityList
}

func (c *Client) setRequestAuthorization(req *http.Request) {
	if c.uid != "" && c.accessToken != "" {
		req.Header.Set("X-Pm-Uid", c.uid)
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
}

func (c *Client) setHumanVerification(req *http.Request) {
	if hv := c.HumanVerification; hv != nil {
		req.Header.Set("X-Pm-Human-Verification-Token", hv.Token)
		req.Header.Set("X-Pm-Human-Verification-Token-Type", strings.Join(hv.Methods, ","))
	}
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.RootURL+path, body)
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Printf(">> %v %v\n", req.Method, req.URL.Path)
	}

	req.Header.Set("X-Pm-Appversion", c.AppVersion)
	req.Header.Set(headerAPIVersion, strconv.Itoa(Version))
	c.setRequestAuthorization(req)
	return req, nil
}

func (c *Client) newJSONRequest(method, path string, body interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, err
	}
	b := buf.Bytes()

	req, err := c.newRequest(method, path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Print(string(b))
	}

	req.Header.Set("Content-Type", "application/json")
	req.GetBody = func() (io.ReadCloser, error) {
		return ioutil.NopCloser(bytes.NewReader(b)), nil
	}
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return resp, err
	}

	// Check if access token has expired
	_, hasAuth := req.Header["Authorization"]
	canRetry := req.Body == nil || req.GetBody != nil
	if resp.StatusCode == http.StatusUnauthorized && hasAuth && c.ReAuth != nil && canRetry {
		resp.Body.Close()
		c.accessToken = ""
		if err := c.ReAuth(); err != nil {
			return resp, err
		}
		c.setRequestAuthorization(req) // Access token has changed
		if req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				return resp, err
			}
			req.Body = body
		}
		return c.do(req)
	}

	return resp, nil
}

func (c *Client) doJSON(req *http.Request, respData interface{}) error {
	req.Header.Set("Accept", "application/json")

	if respData == nil {
		respData = new(resp)
	}

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
		return err
	}

	if c.Debug {
		log.Printf("<< %v %v", req.Method, req.URL.Path)
		log.Printf("%#v", respData)
	}

	if maybeError, ok := respData.(maybeError); ok {
		if err := maybeError.Err(); err != nil {
			if apiErr, ok := err.(*APIError); ok && apiErr.HumanVerification() != nil {
				// Not a failure per se: callers are expected to prompt the user
				return err
			}
			log.Printf("request failed: %v %v: %v", req.Method, req.URL.String(), err)
			return err
		}
	}
	return nil
}
