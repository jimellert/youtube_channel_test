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


type YoutubeTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`   // If zero the token has no (known) expiry time.
}


//type CacheFile string

func (t YoutubeTokens) ReadFile() error {
	file, err := os.Open (cacheFilename)
	if err != nil {
		err = fmt.Errorf ("YoutubeTokens.ReadFile: %v", err)
		return err
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(t); err != nil {
		err = fmt.Errorf ("YoutubeTokens.ReadFile: %v", err)
	}
	return err
}

func (t YoutubeTokens) WriteFile() error {
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
func updateToken (config *Config, tokens *YoutubeTokens, v url.Values) error {

fmt.Printf ("updateToken: 0.  values: %v\n", v)

//	v.Set("client_id", t.ClientId)

//	bustedAuth := !providerAuthHeaderWorks(t.TokenURL)
//	if bustedAuth {
//		v.Set("client_secret", t.ClientSecret)
//	}
	//client := &http.Client{Transport: t.transport()}
	client := &http.Client{}
	req, err := http.NewRequest ("POST", config.TokenURI, strings.NewReader(v.Encode()))
	if err != nil {
		fmt.Printf ("updateToken: Http request setup failed: %v\n", err)
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
//	if !bustedAuth {
//		req.SetBasicAuth(t.ClientId, t.ClientSecret)
//	}

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
	tokens.AccessToken = b.Access
	// Don't overwrite `RefreshToken` with an empty value
	if b.Refresh != "" {
		tokens.RefreshToken = b.Refresh
	}
	if b.ExpiresInSec == 0 {
		tokens.Expiry = time.Time{}
	} else {
		tokens.Expiry = time.Now().Add(time.Duration(b.ExpiresInSec) * time.Second)
	}
fmt.Printf ("updateToken: 4.\n")
//	if b.id != "" {
//		if tokens.Extra == nil {
//			tokens.Extra = make(map[string]string)
//		}
//		tokens.Extra["id_token"] = b.id
//	}
	return nil
}



// Exchange takes an auth-code and gets access-token from the remote server.
//func (t *Transport) Exchange(code string) (*Token, error) {
func ExchangeAuthCodeToAccessToken (config *Config, authCode string) (*YoutubeTokens, error) {
	tokens := new(YoutubeTokens)

	err := updateToken (config, tokens, url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {config.ClientId},
		"client_secret":{config.ClientSecret},
		"redirect_uri": {config.RedirectURI},
		"scope":        {youtube.YoutubeReadonlyScope},
		"code":         {authCode},
	})
	if err != nil {
		fmt.Printf ("ExchangeAuthCodeToAccessToken: updateToken failed: %v\n", err)
		return nil, err
	}

	if err = tokens.WriteFile(); err != nil {
		fmt.Printf ("ExchangeAuthCodeToAccessToken: write cache failed: %v", err)
	}

	return tokens, err
}


// buildOAuthHTTPClient takes the user through the three-legged OAuth flow.
// It opens a browser in the native OS or outputs a URL, then blocks until
// the redirect completes to the /oauth2callback URI.
// It returns an instance of an HTTP client that can be passed to the
// constructor of the YouTube client.
func buildOAuthHTTPClient (config *Config) (*http.Client, error) {

//	config, err := readConfig(scope)
//	if err != nil {
//		msg := fmt.Sprintf("Cannot read configuration file: %v", err)
//		return nil, errors.New(msg)
//	}

//	transport := &oauth.Transport{Config: config}

	// Try to read the token from the cache file.
	// If an error occurs, do the three-legged OAuth flow because
	// the token is invalid or doesn't exist.
//	token, err := config.TokenCache.Token()

	// Start web server.
	// This is how this program receives the authorization code
	// when the browser redirects.
	codeCh, err := startWebServer()
	if err != nil {
		return nil, err
	}

	// Open url in browser
	err = openURL(config.MakeAuthURI())
	if err != nil {
		fmt.Println("Visit the URL below to get a authCode.",
			" This program will pause until the site is visted.")
	} else {
		fmt.Println("Your browser has been opened to an authorization URL.",
			" This program will resume once authorization has been provided.\n")
	}
	fmt.Printf("buildOAuthHTTPClient: %v\n", config.MakeAuthURI())

	// Wait for the web server to get the authCode.
	authCode := <-codeCh



	// This code caches the authorization code on the local
	// filesystem, if necessary, as long as the TokenCache
	// attribute in the config is set.
	tokens, err := ExchangeAuthCodeToAccessToken (config, authCode)
	if err != nil {
		return nil, err
	}

	fmt.Printf ("buildOAuthHTTPClient: tokens: %+v\n", tokens)

//	transport.Token = token
//	return transport.Client(), nil
	return &http.Client{}, nil
}




