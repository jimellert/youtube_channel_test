package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
//	"code.google.com/p/google-api-go-client/youtube/v3"
)

const missingClientSecretsMessage = `
Please configure OAuth 2.0

To make this sample run, you need to populate the client_secrets.json file
found at:

   %v

with information from the Google Developers Console
https://cloud.google.com/console

For more information about the client_secrets.json file format, please visit:
https://developers.google.com/api-client-library/python/guide/aaa_client_secrets
`

const cacheFilename = "../accessTokens.json"


// providerAuthHeaderWorks reports whether the OAuth2 server identified by the tokenURL
// implements the OAuth2 spec correctly
// See https://code.google.com/p/goauth2/issues/detail?id=31 for background.
// In summary:
// - Reddit only accepts client secret in the Authorization header
// - Dropbox accepts either it in URL param or Auth header, but not both.
// - Google only accepts URL param (not spec compliant?), not Auth header
func providerAuthHeaderWorks (tokenURL string) bool {
    if strings.HasPrefix(tokenURL, "https://accounts.google.com/") ||
		strings.HasPrefix(tokenURL, "https://github.com/") ||
		strings.HasPrefix(tokenURL, "https://api.instagram.com/") ||
		strings.HasPrefix(tokenURL, "https://www.douban.com/") {
		// Some sites fail to implement the OAuth2 spec fully.
		return false
	}

	// Assume the provider implements the spec properly
	// otherwise. We can add more exceptions as they're
	// discovered. We will _not_ be adding configurable hooks
	// to this package to let users select server bugs.
	return true
}



// YoutubeTokens store the tokens needed to make youtube API calls.
type YoutubeTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`   // 0 = no expiry time.
}

func (t *YoutubeTokens) ReadFile() error {
	file, err := os.Open (cacheFilename)
	if err != nil {
		err = fmt.Errorf ("YoutubeTokens.ReadFile: %v", err)
		return err
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(&t); err != nil {
		err = fmt.Errorf ("YoutubeTokens.ReadFile: %v", err)
	}
	return err
}

func (t *YoutubeTokens) WriteFile() error {
	file, err := os.OpenFile(cacheFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		err = fmt.Errorf ("YoutubeTokens.ReadFile: %v", err)
		return err
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(t); err != nil {
		err = fmt.Errorf ("YoutubeTokens.ReadFile: %v", err)
	}
	if err := file.Close(); err != nil {
		err = fmt.Errorf ("YoutubeTokens.ReadFile: %v", err)
	}
	return err
}

// Expired reports whether the token has expired or is invalid.
func (t *YoutubeTokens) Expired() bool {
	return true		// Disable this check for now.

    if t.AccessToken == "" {
		return true
	}
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Before(time.Now())
}




// ClientConfig is a data structure definition for the client_secrets.json file.
// The code unmarshals the JSON configuration file into this structure.
type Config struct {
	ClientId     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURI  string   `json:"redirect_uri"`
	AuthURI      string   `json:"auth_uri"`
	TokenURI     string   `json:"token_uri"`
}


// readConfig reads the configuration from clientSecretsFile.
// It returns an oauth configuration object for use with the Google API client.
func readConfig(filename string) (*Config, error) {
	// Read the secrets file
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		pwd, _ := os.Getwd()
		fullPath := filepath.Join(pwd, filename)
		return nil, fmt.Errorf(missingClientSecretsMessage, fullPath)
	}

	cfg := new(Config)
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	if len(cfg.ClientId) == 0 {
		return nil, errors.New("readConfig: No client_id in config file.")
	}
	if len(cfg.ClientSecret) == 0 {
		return nil, errors.New("readConfig: No client_secret in config file.")
	}
	if len(cfg.RedirectURI) == 0 {
		return nil, errors.New("readConfig: No redirect_uri in config file.")
	}
	if len(cfg.AuthURI) == 0 {
		return nil, errors.New("readConfig: No auth_uri in config file.")
	}
	if len(cfg.TokenURI) == 0 {
		return nil, errors.New("readConfig: No token_uri in config file.")
	}

	return &Config{
		ClientId:     cfg.ClientId,
		ClientSecret: cfg.ClientSecret,
		AuthURI:      cfg.AuthURI,
		TokenURI:     cfg.TokenURI,
		RedirectURI:  cfg.RedirectURI,
	}, nil
}




// Transport implements http.RoundTripper. When configured with a valid
// Config and Token it can be used to make authenticated HTTP requests.
//
//  t := &oauth.Transport{config}
//      t.Exchange(code)
//      // t now contains a valid Token
//  r, _, err := t.Client().Get("http://example.org/url/requiring/auth")
//
// It will automatically refresh the Token if it can,
// updating the supplied Token in place.
type Transport struct {
	*Config
	*YoutubeTokens

	// mu guards modifying the token.
	mu sync.Mutex

	// Transport is the HTTP transport to use when making requests.
	// It will default to http.DefaultTransport if nil.
	// (It should never be an oauth.Transport.)
	Transport http.RoundTripper
}

// Client returns an *http.Client that makes OAuth-authenticated requests.
func (t *Transport) Client() *http.Client {
	return &http.Client{Transport: t}
}

func (t *Transport) transport() http.RoundTripper {
	if t.Transport != nil {
		return t.Transport
	}
	return http.DefaultTransport
}


// RoundTrip executes a single HTTP transaction using the Transport's
// Token as authorization headers.
//
// This method will attempt to renew the Token if it has expired and may return
// an error related to that Token renewal before attempting the client request.
// If the Token cannot be renewed a non-nil os.Error value will be returned.
// If the Token is invalid callers should expect HTTP-level errors,
// as indicated by the Response's StatusCode.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	accessToken, err := t.getAccessToken()
	if err != nil {
		return nil, err
	}
	// To set the Authorization header, we must make a copy of the Request
	// so that we don't modify the Request we were given.
	// This is required by the specification of http.RoundTripper.
	req = cloneRequest(req)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Make the HTTP request.
	return t.transport().RoundTrip(req)
}

func (t *Transport) getAccessToken() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.YoutubeTokens == nil {
		if t.Config == nil {
			return "", fmt.Errorf ("getAccessToken: no Config supplied.")
		}
		if t.YoutubeTokens == nil {
			return "", fmt.Errorf ("getAccessToken: no Token supplied.")
		}
		err := t.YoutubeTokens.ReadFile()
		if err != nil {
			return "", err
		}
	}

	// Refresh the Token if it has expired.
	if t.Expired() {
		if err := t.Refresh(); err != nil {
			return "", err
		}
	}
	if t.AccessToken == "" {
		return "", errors.New("no access token obtained from refresh")
	}
	return t.AccessToken, nil
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}
	return r2
}

// Refresh renews the Transport's AccessToken using its RefreshToken.
func (t *Transport) Refresh() error {
	if t.YoutubeTokens == nil {
		return fmt.Errorf ("Refresh: no existing Token")
	}
	if t.RefreshToken == "" {
		return fmt.Errorf ("Refresh: Token expired; butno Refresh Token")
	}
	if t.Config == nil {
		return fmt.Errorf ("Refresh: no Config supplied")
	}

	err := t.updateToken (url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
	})
	if err != nil {
		return err
	}
	if t.YoutubeTokens != nil {
		return t.YoutubeTokens.WriteFile()
	}
	return nil
}




// updateToken mutates both tok and v.
func (t *Transport) updateToken (v url.Values) error {
	v.Set ("client_id", t.Config.ClientId)

	bustedAuth := !providerAuthHeaderWorks (t.Config.TokenURI)
	if bustedAuth {
		v.Set("client_secret", t.ClientSecret)
	}
	client := &http.Client{Transport: t.transport()}
	req, err := http.NewRequest ("POST", t.Config.TokenURI, strings.NewReader(v.Encode()))
	if err != nil {
		fmt.Printf ("updateToken: Http request setup failed: %v\n", err)
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !bustedAuth {
		req.SetBasicAuth(t.ClientId, t.ClientSecret)
	}

	var b struct {
		Access       string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresInSec int64  `json:"expires_in"`
		Refresh      string `json:"refresh_token"`
	}

	r, err := client.Do(req)
	if err != nil {
		fmt.Printf ("updateToken: Http request failed: %v\n", err)
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return errors.New ("updateToken: " + "Unexpected HTTP status " + r.Status)
	}

	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		fmt.Printf ("updateToken: Http read failed: %v\n", err)
		return err
	}

	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))

	switch contentType {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			fmt.Printf ("updateToken: Http parse failed: %v\n", err)
			return err
		}

		b.Access = vals.Get("access_token")
		b.Refresh = vals.Get("refresh_token")
		b.ExpiresInSec, _ = strconv.ParseInt(vals.Get("expires_in"), 10, 64)
		b.TokenType = vals.Get("token_type")

	case "application/json":
		if err = json.Unmarshal(body, &b); err != nil {
			return fmt.Errorf("updateToken: Http json unmarshal failed: %q, %v", body, err)
		}

	default:
		return fmt.Errorf("updateToken: Unexpected content type from server: %q", body)
	}


	if b.Access == "" {
		return errors.New("updateToken: Empty access token from authorization server.")
	}
	t.YoutubeTokens.AccessToken = b.Access
	// Don't overwrite `RefreshToken` with an empty value
	if b.Refresh != "" {
		t.YoutubeTokens.RefreshToken = b.Refresh
	}
	if b.ExpiresInSec == 0 {
		t.YoutubeTokens.Expiry = time.Time{}
	} else {
		t.YoutubeTokens.Expiry = time.Now().Add(time.Duration(b.ExpiresInSec) * time.Second)
	}
	return nil
}



// buildOAuthHTTPClient takes the user through the three-legged OAuth flow.
// It opens a browser in the native OS or outputs a URL, then blocks until
// the redirect completes to the /oauth2callback URI.
// It returns an instance of an HTTP client that can be passed to the
// constructor of the YouTube client.
func buildOAuthHTTPClient (config *Config) (*http.Client, error) {

	transport := &Transport{Config: config}

	// Try to read the token from the cache file.
	// If an error occurs, do the three-legged OAuth flow because
	// the token is invalid or doesn't exist.
	transport.YoutubeTokens = new(YoutubeTokens)
	if err := transport.YoutubeTokens.ReadFile(); err != nil {
		fmt.Printf ("buildOAuthHTTPClient: read cache failed: %v", err)
		return nil, err
	}

	return transport.Client(), nil
}




