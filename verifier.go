package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	keyfunc "github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

const (
	cacheKeyKeyfunc = "key_func"

	defaultWellKnownEndpoint = "/.well-known/openid-configuration"
)

// JWT represents the claims on a JWT.
type JWT struct {
	Claims map[string]any
}

// Cache is used to cache values.
type Cache interface {
	Set(ctx context.Context, key string, value any)
	Get(ctx context.Context, key string) (any, bool)
}

// Option is use to configure a Client when passed into
// NewClient.
type Option func(*Verifier)

// WithHTTPClient sets the HTTP client that the Client should use.
func WithHTTPClient(client *http.Client) Option {
	return func(j *Verifier) {
		j.client = client
	}
}

// WithCache sets the cache that the Client should use.
func WithCache(cache Cache) Option {
	return func(j *Verifier) {
		j.cache = cache
	}
}

// WithOIDCWellKnownEndpoint sets the URL path to the OIDC Discovery well-known
// endpoint. Defaults to /.well-known/openid-configuration.
func WithOIDCWellKnownEndpoint(wellKnownEndpoint string) Option {
	return func(j *Verifier) {
		j.wellKnownEndpoint = wellKnownEndpoint
	}
}

// WithUseJSONNumber will set the UseNumber flag to true in the JSON decoder,
// so any numbers in the parsed claims will be json.Numbers.
func WithUseJSONNumber() Option {
	return func(j *Verifier) {
		j.useJSONNumber = true
	}
}

// Verifier is used to parse and verify JWT tokens issued by Okta.
type Verifier struct {
	client            *http.Client
	issuer            string
	wellKnownEndpoint string
	cache             Cache
	useJSONNumber     bool
	now               func() time.Time
}

// New creates a new Verifier.
func New(issuer string, opts ...Option) Verifier {
	v := Verifier{
		issuer:            issuer,
		client:            http.DefaultClient,
		wellKnownEndpoint: defaultWellKnownEndpoint,
		cache:             NewDefaultCache(),
		now:               time.Now,
	}

	for _, opt := range opts {
		opt(&v)
	}

	return v
}

// ParseAndVerify will parse the JWT and verify the claims using all provided
// rules and return the parsed JWT. It will only verify the claims according to
// the provided rules. If no rules are provided, it will not verify any of the
// claims.
func (j Verifier) ParseAndVerify(ctx context.Context, token string, rules ...ClaimRule) (JWT, error) {
	parsed, err := j.parseJWT(ctx, token)
	if err != nil {
		return JWT{}, err
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return JWT{}, fmt.Errorf("parsed claims are not %T", claims)
	}

	verificationErrors := make([]string, 0)
	for _, rule := range rules {
		v, ok := claims[rule.Key]
		if !ok {
			verificationErrors = append(verificationErrors, fmt.Sprintf("claim '%s' not found", rule.Key))
			continue
		}

		if rule.Rule == nil {
			continue
		}

		if err = rule.Rule(v); err != nil {
			verificationErrors = append(
				verificationErrors,
				fmt.Sprintf("claim '%s' is invalid: %s", rule.Key, err.Error()),
			)
		}
	}

	if len(verificationErrors) != 0 {
		return JWT{}, errors.New(strings.Join(verificationErrors, "; "))
	}

	return JWT{Claims: claims}, nil
}

func (j Verifier) parseJWT(ctx context.Context, tokenString string) (*jwt.Token, error) {
	kf, err := j.getKeyfunc(ctx)
	if err != nil {
		return nil, err
	}

	options := []jwt.ParserOption{jwt.WithoutClaimsValidation()}
	if j.useJSONNumber {
		options = append(options, jwt.WithJSONNumber())
	}

	token, err := jwt.Parse(tokenString, kf, options...)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %w", err)
	}

	return token, nil
}

func (j Verifier) getKeyfunc(ctx context.Context) (jwt.Keyfunc, error) {
	if v, ok := j.cache.Get(ctx, cacheKeyKeyfunc); ok {
		return v.(jwt.Keyfunc), nil
	}

	jwksURI, err := j.getJWKSURI(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting jwks uri: %w", err)
	}

	data, err := j.getJWKS(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("getting jwks: %w", err)
	}

	fn, err := keyfunc.NewJWKSetJSON(data)
	if err != nil {
		return nil, fmt.Errorf("creating new key func: %w", err)
	}

	j.cache.Set(ctx, cacheKeyKeyfunc, jwt.Keyfunc(fn.Keyfunc))

	return fn.Keyfunc, nil
}

func (j Verifier) getJWKSURI(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.issuer, nil)
	if err != nil {
		return "", fmt.Errorf("creating new *http.Request: %w", err)
	}

	req.URL.Path = path.Join("/", req.URL.Path, j.wellKnownEndpoint)

	resp, err := j.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("making http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var data []byte
		data, err = io.ReadAll(resp.Body)
		if err == nil {
			return "", fmt.Errorf(
				"expected status code %d but got status code %d with data: %s",
				http.StatusOK,
				resp.StatusCode,
				string(data),
			)
		}
		return "", fmt.Errorf(
			"expected status code %d but got status code %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	var metadata struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return "", fmt.Errorf("json-decoding response body: %w", err)
	}

	return metadata.JWKSURI, nil
}

func (j Verifier) getJWKS(ctx context.Context, jwksURI string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("creating new *http.Request: %w", err)
	}

	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var data []byte
		data, err = io.ReadAll(resp.Body)
		if err == nil {
			return nil, fmt.Errorf(
				"expected status code %d but got status code %d with data: %s",
				http.StatusOK,
				resp.StatusCode,
				string(data),
			)
		}
		return nil, fmt.Errorf(
			"expected status code %d but got status code %d",
			http.StatusOK,
			resp.StatusCode,
		)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return json.RawMessage(data), nil
}
