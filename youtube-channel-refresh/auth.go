package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"code.google.com/p/google-api-go-client/youtube/v3"
//	"code.google.com/p/goauth2/oauth"
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

//var (
//	clientSecretsFile = flag.String("secrets", "client_secrets.json", "Client Secrets configuration")
//	cacheFile         = flag.String("cache", "request.token", "Token cache file")
//)

const cacheFilename = "../accessTokens.json"

//httpTransport  http.RoundTripper{}


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



//// Config is the configuration of an OAuth consumer.
//type Config struct {
//	// ClientId is the OAuth client identifier used when communicating with
//	// the configured OAuth provider.
//	ClientId string
//
//	// ClientSecret is the OAuth client secret used when communicating with
//	// the configured OAuth provider.
//	ClientSecret string
//
//	// Scope identifies the level of access being requested. Multiple scope
//	// values should be provided as a space-delimited string.
//	Scope string
//
//	// AuthURL is the URL the user will be directed to in order to grant
//	// access.
//	AuthURL string
//
//	// TokenURL is the URL used to retrieve OAuth tokens.
//	TokenURL string
//
//	// RedirectURL is the URL to which the user will be returned after
//	// granting (or denying) access.
//	RedirectURL string
//
//	// TokenCache allows tokens to be cached for subsequent requests.
//	TokenCache Cache
//
//	// AccessType is an OAuth extension that gets sent as the
//	// "access_type" field in the URL from AuthCodeURL.
//	// See https://developers.google.com/accounts/docs/OAuth2WebServer.
//	// It may be "online" (the default) or "offline".
//	// If your application needs to refresh access tokens when the
//	// user is not present at the browser, then use offline. This
//	// will result in your application obtaining a refresh token
//	// the first time your application exchanges an authorization
//	// code for a user.
//	AccessType string   // "offline"
//
//	// ApprovalPrompt indicates whether the user should be
//	// re-prompted for consent. If set to "auto" (default) the
//	// user will be prompted only if they haven't previously
//	// granted consent and the code can only be exchanged for an
//	// access token.
//	// If set to "force" the user will always be prompted, and the
//	// code can be exchanged for a refresh token.
//	ApprovalPrompt string   // "force"
//}


// Cache specifies the methods that implement a Token cache.
//type Cache interface {
//	Token() (*Token, error)
//	PutToken(*Token) error
//}



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
fmt.Printf ("YoutubeTokens: at: %v, rt: %v, ex: %v\n", t.AccessToken, t.RefreshToken, t.Expiry)
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

//// Config is a root-level configuration object.
//type Config struct {
//	Installed ClientConfig `json:"installed"`
//	Web       ClientConfig `json:"web"`
//}

// MakeAuthURI returns the URI to pass to youtube auth server.
func (c *Config) MakeAuthURI() string {
	url_, err := url.Parse(c.AuthURI)
	if err != nil {
		panic("AuthURL malformed: " + err.Error())
	}
	q := url.Values{
		"response_type":   {"code"},
		"client_id":       {c.ClientId},
		"state":           condVal(""),
		"scope":           condVal(youtube.YoutubeReadonlyScope),
		"redirect_uri":    condVal(c.RedirectURI),
		"access_type":     condVal("offline"),
		"approval_prompt": condVal("force"),
		}.Encode()
	if url_.RawQuery == "" {
		url_.RawQuery = q
	} else {
		url_.RawQuery += "&" + q
	}
	return url_.String()
}

func condVal(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// openURL opens a browser window to the specified location.
// This code originally appeared at:
//   http://stackoverflow.com/questions/10377243/how-can-i-launch-a-process-that-is-not-a-file-in-go
func openURL(url string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", "http://localhost:4001/").Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("Cannot open URL %s on this platform", url)
	}
	return err
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

	fmt.Printf(". . config: %v, data: %s\n", cfg.ClientId, data)

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
//		Scope:        scope,		// youtube.YoutubeReadonlyScope
		AuthURI:      cfg.AuthURI,
		TokenURI:     cfg.TokenURI,
		RedirectURI:  cfg.RedirectURI,
//		TokenCache:   oauth.CacheFile(*cacheFile),
		// Get a refresh token so we can use the access token indefinitely
//		AccessType: "offline",
		// If we want a refresh token, we must set this attribute
		// to force an approval prompt or the code won't work.
//		ApprovalPrompt: "force",
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

//// Exchange takes a code and gets access Token from the remote server.
//func (t *Transport) Exchange(code string) (*Token, error) {
//	fmt.Printf("auth.go::Exchange\n")
//	if t.Config == nil {
//		return nil, OAuthError{"Exchange", "no Config supplied"}
//	}
//
//	// If the transport or the cache already has a token, it is
//	// passed to `updateToken` to preserve existing refresh token.
//	tok := t.Token
//	if tok == nil && t.TokenCache != nil {
//		tok, _ = t.TokenCache.Token()
//	}
//	if tok == nil {
//		tok = new(Token)
//	}
//	err := t.updateToken(tok, url.Values{
//		"grant_type":   {"authorization_code"},
//		"redirect_uri": {t.RedirectURL},
//		"scope":        {t.Scope},
//		"code":         {code},
//	})
//	if err != nil {
//		return nil, err
//	}
//	t.Token = tok
//	if t.TokenCache != nil {
//		return tok, t.TokenCache.PutToken(tok)
//	}
//	return tok, nil
//}

// RoundTrip executes a single HTTP transaction using the Transport's
// Token as authorization headers.
//
// This method will attempt to renew the Token if it has expired and may return
// an error related to that Token renewal before attempting the client request.
// If the Token cannot be renewed a non-nil os.Error value will be returned.
// If the Token is invalid callers should expect HTTP-level errors,
// as indicated by the Response's StatusCode.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Printf("auth.go::RoundTrip\n")

	fmt.Printf("auth.go: call getAccessToken\n")
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
	fmt.Printf("auth.go::getAccessToken\n")
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.YoutubeTokens == nil {
		if t.Config == nil {
			return "", fmt.Errorf ("getAccessToken: no Config supplied.")
		}
		if t.YoutubeTokens == nil {
			return "", fmt.Errorf ("getAccessToken: no Token supplied.")
		}
//		var err error
		err := t.YoutubeTokens.ReadFile()
		if err != nil {
			return "", err
		}
fmt.Printf ("YoutubeTokens 1: at: %v, rt: %v, ex: %v\n", t.AccessToken, t.RefreshToken, t.Expiry)
	}

	// Refresh the Token if it has expired.
	fmt.Printf("auth.go::getAccessToken call Expired\n")
	if t.Expired() {
		fmt.Printf("auth.go::getAccessToken call Refresh\n")
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
	fmt.Printf("auth.go::Refresh\n")
	if t.YoutubeTokens == nil {
		return fmt.Errorf ("Refresh: no existing Token")
	}
	if t.RefreshToken == "" {
		return fmt.Errorf ("Refresh: Token expired; butno Refresh Token")
	}
	if t.Config == nil {
		return fmt.Errorf ("Refresh: no Config supplied")
	}

	fmt.Printf("auth.go::Refresh: call updateToken\n")
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








// startWebServer starts a web server that listens on http://localhost:8080.
// The webserver waits for an oauth code in the three-legged auth flow.
func startWebServer() (codeCh chan string, err error) {
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		return nil, err
	}
	codeCh = make(chan string)
	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := r.FormValue("code")
		codeCh <- code // send code to OAuth flow
		listener.Close()
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Received code: %v\r\nYou can now safely close this browser window.", code)
	}))

	return codeCh, nil
}



// updateToken mutates both tok and v.
//func (t *Transport) updateToken(tok *YoutubeTokens, v url.Values) error {
func (t *Transport) updateToken (v url.Values) error {

fmt.Printf ("updateToken: 0.  values: %v\n", v)

	v.Set ("client_id", t.Config.ClientId)

	bustedAuth := !providerAuthHeaderWorks (t.Config.TokenURI)
	if bustedAuth {
		v.Set("client_secret", t.ClientSecret)
	}
	client := &http.Client{Transport: t.transport()}
	//client := &http.Client{}
	req, err := http.NewRequest ("POST", t.Config.TokenURI, strings.NewReader(v.Encode()))
	if err != nil {
		fmt.Printf ("updateToken: Http request setup failed: %v\n", err)
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !bustedAuth {
		req.SetBasicAuth(t.ClientId, t.ClientSecret)
	}

fmt.Printf ("updateToken: 1.  req: %v\n", req)
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

fmt.Printf ("updateToken: 2.\n")
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		fmt.Printf ("updateToken: Http read failed: %v\n", err)
		return err
	}

	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
fmt.Printf ("updateToken: 3.  contentType: %v\n", contentType)

	switch contentType {
	case "application/x-www-form-urlencoded", "text/plain":
fmt.Printf ("updateToken: 3.1.\n")
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
fmt.Printf ("updateToken: 3.2.   body: %v\n", string(body))
		if err = json.Unmarshal(body, &b); err != nil {
			return fmt.Errorf("updateToken: Http json unmarshal failed: %q, %v", body, err)
		}
fmt.Printf ("updateToken: 3.2.1.   b: %+v\n", b)

	default:
fmt.Printf ("updateToken: 3.3.\n")
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
fmt.Printf ("updateToken: 4.\n")
//	if b.id != "" {
//		if t.YoutubeTokens.Extra == nil {
//			t.YoutubeTokens.Extra = make(map[string]string)
//		}
//		t.YoutubeTokens.Extra["id_token"] = b.id
//	}
	return nil
}



// Exchange takes an auth-code and gets access-token from the remote server.
//func (t *Transport) Exchange(code string) (*Token, error) {
func (t *Transport) ExchangeAuthCodeToAccessToken (config *Config, authCode string) error {
//	tokens := new(YoutubeTokens)

	err := t.updateToken (url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {config.ClientId},
		"client_secret":{config.ClientSecret},
		"redirect_uri": {config.RedirectURI},
		"scope":        {youtube.YoutubeReadonlyScope},
		"code":         {authCode},
	})
	if err != nil {
		fmt.Printf ("ExchangeAuthCodeToAccessToken: updateToken failed: %v\n", err)
		return err
	}

	if err = t.YoutubeTokens.WriteFile(); err != nil {
		fmt.Printf ("ExchangeAuthCodeToAccessToken: write cache failed: %v", err)
	}

	return err
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
//	token, err := config.TokenCache.Token()
	transport.YoutubeTokens = new(YoutubeTokens)
	if err := transport.YoutubeTokens.ReadFile(); err != nil {
		fmt.Printf ("buildOAuthHTTPClient: read cache failed: %v", err)
		return nil, err
	}

fmt.Printf ("YoutubeTokens 2: at: %v, rt: %v, ex: %v\n", transport.YoutubeTokens.AccessToken, transport.YoutubeTokens.RefreshToken, transport.YoutubeTokens.Expiry)
	// Start web server.
	// This is how this program receives the authorization code
	// when the browser redirects.
//	codeCh, err := startWebServer()
//	if err != nil {
//		return nil, err
//	}

	// Open url in browser
//	err = openURL(config.MakeAuthURI())
//	if err != nil {
//		fmt.Println("Visit the URL below to get a authCode.",
//			" This program will pause until the site is visted.")
//	} else {
//		fmt.Println("Your browser has been opened to an authorization URL.",
//			" This program will resume once authorization has been provided.\n")
//	}
//	fmt.Printf("buildOAuthHTTPClient: %v\n", config.MakeAuthURI())
//
//	// Wait for the web server to get the authCode.
//	authCode := <-codeCh

	// This code caches the authorization code on the local
	// filesystem, if necessary, as long as the TokenCache
	// attribute in the config is set.
//	err := transport.ExchangeAuthCodeToAccessToken (config, authCode)
//	if err != nil {
//		return nil, err
//	}

	fmt.Printf ("buildOAuthHTTPClient: tokens: %+v\n", transport.YoutubeTokens)

	return transport.Client(), nil
}




