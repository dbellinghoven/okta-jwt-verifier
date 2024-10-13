package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestVerifier_ParseAndVerify(t *testing.T) {
	nopHandler := func(http.ResponseWriter, *http.Request) {}

	defaultJWKS := `{"keys":[{"kty":"RSA","e":"AQAB","kid":"ee8d626d","n":"gRda5b0pkgTytDuLrRnNSYhvfMIyM0ASq2ZggY4dVe12JV8N7lyXilyqLKleD-2lziivvzE8O8CdIC2vUf0tBD7VuMyldnZruSEZWCuKJPdgKgy9yPpShmD2NyhbwQIAbievGMJIp_JMwz8MkdY5pzhPECGNgCEtUAmsrrctP5V8HuxaxGt9bb-DdPXkYWXW3MPMSlVpGZ5GiIeTABxqYNG2MSoYeQ9x8O3y488jbassTqxExI_4w9MBQBJR9HIXjWrrrenCcDlMY71rzkbdj3mmcn9xMq2vB5OhfHyHTihbUPLSm83aFWSuW9lE7ogMc93XnrB8evIAk6VfsYlS9Q"},{"kty":"EC","crv":"P-256","kid":"711d48d1","x":"tfXCoBU-wXemeQCkME1gMZWK0-UECCHIkedASZR0t-Q","y":"9xzYtnKQdiQJHCtGwpZWF21eP1fy5x4wC822rCilmBw"},{"kty":"EC","crv":"P-384","kid":"d52c9829","x":"tFx6ev6eLs9sNfdyndn4OgbhV6gPFVn7Ul0VD5vwuplJLbIYeFLI6T42tTaE5_Q4","y":"A0gzB8TqxPX7xMzyHH_FXkYG2iROANH_kQxBovSeus6l_QSyqYlipWpBy9BhY9dz"},{"kty":"RSA","e":"AQAB","kid":"ecac72e5","n":"nLbnTvZAUxdmuAbDDUNAfha6mw0fri3UpV2w1PxilflBuSnXJhzo532-YQITogoanMjy_sQ8kHUhZYHVRR6vLZRBBbl-hP8XWiCe4wwioy7Ey3TiIUYfW-SD6I42XbLt5o-47IR0j5YDXxnX2UU7-UgR_kITBeLDfk0rSp4B0GUhPbP5IDItS0MHHDDS3lhvJomxgEfoNrp0K0Fz_s0K33hfOqc2hD1tSkX-3oDTQVRMF4Nxax3NNw8-ahw6HNMlXlwWfXodgRMvj9pcz8xUYa3C5IlPlZkMumeNCFx1qds6K_eYcU0ss91DdbhhE8amRX1FsnBJNMRUkA5i45xkOIx15rQN230zzh0p71jvtx7wYRr5pdMlwxV0T9Ck5PCmx-GzFazA2X6DJ0Xnn1-cXkRoZHFj_8Mba1dUrNz-NWEk83uW5KT-ZEbX7nzGXtayKWmGb873a8aYPqIsp6bQ_-eRBd8TDT2g9HuPyPr5VKa1p33xKaohz4DGy3t1Qpy3UWnbPXUlh5dLWPKz-TcS9FP5gFhWVo-ZhU03Pn6P34OxHmXGWyQao18dQGqzgD4e9vY3rLhfcjVZJYNlWY2InsNwbYS-DnienPf1ws-miLeXxNKG3tFydoQzHwyOxG6Wc-HBfzL_hOvxINKQamvPasaYWl1LWznMps6elKCgKDc"},{"kty":"EC","crv":"P-521","kid":"c570888f","x":"AHNpXq0J7rikNRlwhaMYDD8LGVAVJzNJ-jEPksUIn2LB2LCdNRzfAhgbxdQcWT9ktlc9M1EhmTLccEqfnWdGL9G1","y":"AfHPUW3GYzzqbTczcYR0nYMVMFVrYsUxv4uiuSNV_XRN3Jf8zeYbbOLJv4S3bUytO7qHY8bfZxPxR9nn3BBTf5ol"}]}`

	cases := map[string]struct {
		token            string
		initMockCache    func(*mockCache)
		jwksHandler      http.HandlerFunc
		newIssuerHandler func(jwksURI string) http.HandlerFunc
		rules            []ClaimRule
		wantErr          string
	}{
		"error getting keyfunc": {
			initMockCache: func(mc *mockCache) {
				mc.On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false)
			},
			jwksHandler: nopHandler,
			newIssuerHandler: func(string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, `{"status":500,"error":"internal server error"}`)
				}
			},
			wantErr: `getting jwks uri: expected status code 200 but got status code 500 with data: {"status":500,"error":"internal server error"}`,
		},
		"parse error": {
			token: "eyJraWQiOiJlZThkI2ZCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJXZWlkb25nIiwiYXVkIjoiVGFzaHVhbiIsImlzcyI6Imp3a3Mtc2VydmljZS5hcHBzcG90LmNvbSIsImlhdCI6MTYzMTM2OTk1NSwianRpIjoiNDY2M2E5MTAtZWU2MC00NzcwLTgxNjktY2I3NDdiMDljZjU0In0.LwD65d5h6U_2Xco81EClMa_1WIW4xXZl8o4b7WzY_7OgPD2tNlByxvGDzP7bKYA9Gj--1mi4Q4li4CAnKJkaHRYB17baC0H5P9lKMPuA6AnChTzLafY6yf-YadA7DmakCtIl7FNcFQQL2DXmh6gS9J6TluFoCIXj83MqETbDWpL28o3XAD_05UP8VLQzH2XzyqWKi97mOuvz-GsDp9mhBYQUgN3csNXt2v2l-bUPWe19SftNej0cxddyGu06tXUtaS6K0oe0TTbaqc3hmfEiu5G0J8U6ztTUMwXkBvaknE640NPgMQJqBaey0E4u0txYgyvMvvxfwtcOrDRYqYPBnB",
			initMockCache: func(mc *mockCache) {
				mc.
					On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false).
					On("Set", cacheKeyKeyfunc, mock.AnythingOfType("jwt.Keyfunc")).Return()
			},
			newIssuerHandler: func(jwksURI string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("content-type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"jwks_uri":%q}`, jwksURI)
				}
			},
			jwksHandler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, defaultJWKS)
			},
			wantErr: "parsing jwt: token is malformed: could not base64 decode header: illegal base64 data at input byte 56",
		},
		"success/no rules": {
			token: "eyJraWQiOiJlZThkNjI2ZCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJXZWlkb25nIiwiYXVkIjoiVGFzaHVhbiIsImlzcyI6Imp3a3Mtc2VydmljZS5hcHBzcG90LmNvbSIsImlhdCI6MTYzMTM2OTk1NSwianRpIjoiNDY2M2E5MTAtZWU2MC00NzcwLTgxNjktY2I3NDdiMDljZjU0In0.LwD65d5h6U_2Xco81EClMa_1WIW4xXZl8o4b7WzY_7OgPD2tNlByxvGDzP7bKYA9Gj--1mi4Q4li4CAnKJkaHRYB17baC0H5P9lKMPuA6AnChTzLafY6yf-YadA7DmakCtIl7FNcFQQL2DXmh6gS9J6TluFoCIXj83MqETbDWpL28o3XAD_05UP8VLQzH2XzyqWKi97mOuvz-GsDp9mhBYQUgN3csNXt2v2l-bUPWe19SftNej0cxddyGu06tXUtaS6K0oe0TTbaqc3hmfEiu5G0J8U6ztTUMwXkBvaknE640NPgMQJqBaey0E4u0txYgyvMvvxfwtcOrDRYqYPBnA",
			initMockCache: func(mc *mockCache) {
				mc.
					On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false).
					On("Set", cacheKeyKeyfunc, mock.AnythingOfType("jwt.Keyfunc")).Return()
			},
			newIssuerHandler: func(jwksURI string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("content-type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"jwks_uri":%q}`, jwksURI)
				}
			},
			jwksHandler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, defaultJWKS)
			},
		},
		"success/fails verification": {
			token: "eyJraWQiOiJlZThkNjI2ZCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJXZWlkb25nIiwiYXVkIjoiVGFzaHVhbiIsImlzcyI6Imp3a3Mtc2VydmljZS5hcHBzcG90LmNvbSIsImlhdCI6MTYzMTM2OTk1NSwianRpIjoiNDY2M2E5MTAtZWU2MC00NzcwLTgxNjktY2I3NDdiMDljZjU0In0.LwD65d5h6U_2Xco81EClMa_1WIW4xXZl8o4b7WzY_7OgPD2tNlByxvGDzP7bKYA9Gj--1mi4Q4li4CAnKJkaHRYB17baC0H5P9lKMPuA6AnChTzLafY6yf-YadA7DmakCtIl7FNcFQQL2DXmh6gS9J6TluFoCIXj83MqETbDWpL28o3XAD_05UP8VLQzH2XzyqWKi97mOuvz-GsDp9mhBYQUgN3csNXt2v2l-bUPWe19SftNej0cxddyGu06tXUtaS6K0oe0TTbaqc3hmfEiu5G0J8U6ztTUMwXkBvaknE640NPgMQJqBaey0E4u0txYgyvMvvxfwtcOrDRYqYPBnA",
			initMockCache: func(mc *mockCache) {
				mc.
					On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false).
					On("Set", cacheKeyKeyfunc, mock.AnythingOfType("jwt.Keyfunc")).Return()
			},
			newIssuerHandler: func(jwksURI string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("content-type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"jwks_uri":%q}`, jwksURI)
				}
			},
			jwksHandler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, defaultJWKS)
			},
			rules: []ClaimRule{
				NewAudienceRule("foo"),
				NewCustomClaimExactMatchRule("sub", "bar"),
			},
			wantErr: "claim 'aud' is invalid: expected 'foo' but got 'Tashuan'; claim 'sub' is invalid: expected 'bar' but got 'Weidong'",
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			var cache mockCache
			if tt.initMockCache != nil {
				tt.initMockCache(&cache)
				defer cache.AssertExpectations(t)
			}

			jwks := httptest.NewServer(tt.jwksHandler)
			defer jwks.Close()

			issuer := httptest.NewServer(tt.newIssuerHandler(jwks.URL))
			defer issuer.Close()

			client := Verifier{
				cache:  &cache,
				issuer: issuer.URL,
				client: http.DefaultClient,
			}

			token, err := client.ParseAndVerify(context.Background(), tt.token, tt.rules...)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			_ = token
		})
	}
}

func TestVerifier_parseJWT(t *testing.T) {
	nopHandler := func(http.ResponseWriter, *http.Request) {}

	defaultJWKS := `{"keys":[{"kty":"RSA","e":"AQAB","kid":"ee8d626d","n":"gRda5b0pkgTytDuLrRnNSYhvfMIyM0ASq2ZggY4dVe12JV8N7lyXilyqLKleD-2lziivvzE8O8CdIC2vUf0tBD7VuMyldnZruSEZWCuKJPdgKgy9yPpShmD2NyhbwQIAbievGMJIp_JMwz8MkdY5pzhPECGNgCEtUAmsrrctP5V8HuxaxGt9bb-DdPXkYWXW3MPMSlVpGZ5GiIeTABxqYNG2MSoYeQ9x8O3y488jbassTqxExI_4w9MBQBJR9HIXjWrrrenCcDlMY71rzkbdj3mmcn9xMq2vB5OhfHyHTihbUPLSm83aFWSuW9lE7ogMc93XnrB8evIAk6VfsYlS9Q"},{"kty":"EC","crv":"P-256","kid":"711d48d1","x":"tfXCoBU-wXemeQCkME1gMZWK0-UECCHIkedASZR0t-Q","y":"9xzYtnKQdiQJHCtGwpZWF21eP1fy5x4wC822rCilmBw"},{"kty":"EC","crv":"P-384","kid":"d52c9829","x":"tFx6ev6eLs9sNfdyndn4OgbhV6gPFVn7Ul0VD5vwuplJLbIYeFLI6T42tTaE5_Q4","y":"A0gzB8TqxPX7xMzyHH_FXkYG2iROANH_kQxBovSeus6l_QSyqYlipWpBy9BhY9dz"},{"kty":"RSA","e":"AQAB","kid":"ecac72e5","n":"nLbnTvZAUxdmuAbDDUNAfha6mw0fri3UpV2w1PxilflBuSnXJhzo532-YQITogoanMjy_sQ8kHUhZYHVRR6vLZRBBbl-hP8XWiCe4wwioy7Ey3TiIUYfW-SD6I42XbLt5o-47IR0j5YDXxnX2UU7-UgR_kITBeLDfk0rSp4B0GUhPbP5IDItS0MHHDDS3lhvJomxgEfoNrp0K0Fz_s0K33hfOqc2hD1tSkX-3oDTQVRMF4Nxax3NNw8-ahw6HNMlXlwWfXodgRMvj9pcz8xUYa3C5IlPlZkMumeNCFx1qds6K_eYcU0ss91DdbhhE8amRX1FsnBJNMRUkA5i45xkOIx15rQN230zzh0p71jvtx7wYRr5pdMlwxV0T9Ck5PCmx-GzFazA2X6DJ0Xnn1-cXkRoZHFj_8Mba1dUrNz-NWEk83uW5KT-ZEbX7nzGXtayKWmGb873a8aYPqIsp6bQ_-eRBd8TDT2g9HuPyPr5VKa1p33xKaohz4DGy3t1Qpy3UWnbPXUlh5dLWPKz-TcS9FP5gFhWVo-ZhU03Pn6P34OxHmXGWyQao18dQGqzgD4e9vY3rLhfcjVZJYNlWY2InsNwbYS-DnienPf1ws-miLeXxNKG3tFydoQzHwyOxG6Wc-HBfzL_hOvxINKQamvPasaYWl1LWznMps6elKCgKDc"},{"kty":"EC","crv":"P-521","kid":"c570888f","x":"AHNpXq0J7rikNRlwhaMYDD8LGVAVJzNJ-jEPksUIn2LB2LCdNRzfAhgbxdQcWT9ktlc9M1EhmTLccEqfnWdGL9G1","y":"AfHPUW3GYzzqbTczcYR0nYMVMFVrYsUxv4uiuSNV_XRN3Jf8zeYbbOLJv4S3bUytO7qHY8bfZxPxR9nn3BBTf5ol"}]}`

	cases := map[string]struct {
		token            string
		initMockCache    func(*mockCache)
		jwksHandler      http.HandlerFunc
		newIssuerHandler func(jwksURI string) http.HandlerFunc
		wantErr          string
	}{
		"error getting keyfunc": {
			initMockCache: func(mc *mockCache) {
				mc.On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false)
			},
			jwksHandler: nopHandler,
			newIssuerHandler: func(string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, `{"status":500,"error":"internal server error"}`)
				}
			},
			wantErr: `getting jwks uri: expected status code 200 but got status code 500 with data: {"status":500,"error":"internal server error"}`,
		},
		"parse error": {
			token: "deadbeef",
			initMockCache: func(mc *mockCache) {
				mc.
					On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false).
					On("Set", cacheKeyKeyfunc, mock.AnythingOfType("jwt.Keyfunc")).Return()
			},
			newIssuerHandler: func(jwksURI string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("content-type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"jwks_uri":%q}`, jwksURI)
				}
			},
			jwksHandler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, defaultJWKS)
			},
			wantErr: "parsing jwt: token is malformed: token contains an invalid number of segments",
		},
		"success": {
			token: "eyJraWQiOiJlZThkNjI2ZCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJXZWlkb25nIiwiYXVkIjoiVGFzaHVhbiIsImlzcyI6Imp3a3Mtc2VydmljZS5hcHBzcG90LmNvbSIsImlhdCI6MTYzMTM2OTk1NSwianRpIjoiNDY2M2E5MTAtZWU2MC00NzcwLTgxNjktY2I3NDdiMDljZjU0In0.LwD65d5h6U_2Xco81EClMa_1WIW4xXZl8o4b7WzY_7OgPD2tNlByxvGDzP7bKYA9Gj--1mi4Q4li4CAnKJkaHRYB17baC0H5P9lKMPuA6AnChTzLafY6yf-YadA7DmakCtIl7FNcFQQL2DXmh6gS9J6TluFoCIXj83MqETbDWpL28o3XAD_05UP8VLQzH2XzyqWKi97mOuvz-GsDp9mhBYQUgN3csNXt2v2l-bUPWe19SftNej0cxddyGu06tXUtaS6K0oe0TTbaqc3hmfEiu5G0J8U6ztTUMwXkBvaknE640NPgMQJqBaey0E4u0txYgyvMvvxfwtcOrDRYqYPBnA",
			initMockCache: func(mc *mockCache) {
				mc.
					On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false).
					On("Set", cacheKeyKeyfunc, mock.AnythingOfType("jwt.Keyfunc")).Return()
			},
			newIssuerHandler: func(jwksURI string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("content-type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"jwks_uri":%q}`, jwksURI)
				}
			},
			jwksHandler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, defaultJWKS)
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			var cache mockCache
			if tt.initMockCache != nil {
				tt.initMockCache(&cache)
				defer cache.AssertExpectations(t)
			}

			jwks := httptest.NewServer(tt.jwksHandler)
			defer jwks.Close()

			issuer := httptest.NewServer(tt.newIssuerHandler(jwks.URL))
			defer issuer.Close()

			client := Verifier{
				cache:  &cache,
				issuer: issuer.URL,
				client: http.DefaultClient,
			}

			token, err := client.ParseAndVerify(context.Background(), tt.token)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			_ = token
		})
	}
}

func TestVerifier_getKeyfunc(t *testing.T) {
	nopHandler := func(http.ResponseWriter, *http.Request) {}

	cases := map[string]struct {
		initMockCache    func(*mockCache)
		jwksHandler      http.HandlerFunc
		newIssuerHandler func(jwksURI string) http.HandlerFunc
		wantErr          string
	}{
		"key func in cache": {
			initMockCache: func(mc *mockCache) {
				mc.
					On("Get", cacheKeyKeyfunc).
					Return(
						jwt.Keyfunc(func(*jwt.Token) (interface{}, error) {
							return nil, nil
						}),
						true,
						nil,
					)
			},
			jwksHandler: nopHandler,
			newIssuerHandler: func(string) http.HandlerFunc {
				return nopHandler
			},
		},
		"failed to get jwks uri": {
			initMockCache: func(mc *mockCache) {
				mc.
					On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false)
			},
			newIssuerHandler: func(string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, `{"status":500,"error":"internal server error"}`)
				}
			},
			wantErr: `getting jwks uri: expected status code 200 but got status code 500 with data: {"status":500,"error":"internal server error"}`,
		},
		"failed to get jwks": {
			initMockCache: func(mc *mockCache) {
				mc.
					On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false)
			},
			newIssuerHandler: func(jwksURI string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("content-type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"jwks_uri":%q}`, jwksURI)
				}
			},
			jwksHandler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"status":500,"error":"internal server error"}`)
			},
			wantErr: `getting jwks: expected status code 200 but got status code 500 with data: {"status":500,"error":"internal server error"}`,
		},
		"success": {
			initMockCache: func(mc *mockCache) {
				mc.
					On("Get", cacheKeyKeyfunc).Return(jwt.Keyfunc(nil), false).
					On("Set", cacheKeyKeyfunc, mock.AnythingOfType("jwt.Keyfunc")).Return()
			},
			newIssuerHandler: func(jwksURI string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("content-type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"jwks_uri":%q}`, jwksURI)
				}
			},
			jwksHandler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, `{"keys":[{"kty":"RSA","e":"AQAB","kid":"ee8d626d","n":"gRda5b0pkgTytDuLrRnNSYhvfMIyM0ASq2ZggY4dVe12JV8N7lyXilyqLKleD-2lziivvzE8O8CdIC2vUf0tBD7VuMyldnZruSEZWCuKJPdgKgy9yPpShmD2NyhbwQIAbievGMJIp_JMwz8MkdY5pzhPECGNgCEtUAmsrrctP5V8HuxaxGt9bb-DdPXkYWXW3MPMSlVpGZ5GiIeTABxqYNG2MSoYeQ9x8O3y488jbassTqxExI_4w9MBQBJR9HIXjWrrrenCcDlMY71rzkbdj3mmcn9xMq2vB5OhfHyHTihbUPLSm83aFWSuW9lE7ogMc93XnrB8evIAk6VfsYlS9Q"},{"kty":"EC","crv":"P-256","kid":"711d48d1","x":"tfXCoBU-wXemeQCkME1gMZWK0-UECCHIkedASZR0t-Q","y":"9xzYtnKQdiQJHCtGwpZWF21eP1fy5x4wC822rCilmBw"},{"kty":"EC","crv":"P-384","kid":"d52c9829","x":"tFx6ev6eLs9sNfdyndn4OgbhV6gPFVn7Ul0VD5vwuplJLbIYeFLI6T42tTaE5_Q4","y":"A0gzB8TqxPX7xMzyHH_FXkYG2iROANH_kQxBovSeus6l_QSyqYlipWpBy9BhY9dz"},{"kty":"RSA","e":"AQAB","kid":"ecac72e5","n":"nLbnTvZAUxdmuAbDDUNAfha6mw0fri3UpV2w1PxilflBuSnXJhzo532-YQITogoanMjy_sQ8kHUhZYHVRR6vLZRBBbl-hP8XWiCe4wwioy7Ey3TiIUYfW-SD6I42XbLt5o-47IR0j5YDXxnX2UU7-UgR_kITBeLDfk0rSp4B0GUhPbP5IDItS0MHHDDS3lhvJomxgEfoNrp0K0Fz_s0K33hfOqc2hD1tSkX-3oDTQVRMF4Nxax3NNw8-ahw6HNMlXlwWfXodgRMvj9pcz8xUYa3C5IlPlZkMumeNCFx1qds6K_eYcU0ss91DdbhhE8amRX1FsnBJNMRUkA5i45xkOIx15rQN230zzh0p71jvtx7wYRr5pdMlwxV0T9Ck5PCmx-GzFazA2X6DJ0Xnn1-cXkRoZHFj_8Mba1dUrNz-NWEk83uW5KT-ZEbX7nzGXtayKWmGb873a8aYPqIsp6bQ_-eRBd8TDT2g9HuPyPr5VKa1p33xKaohz4DGy3t1Qpy3UWnbPXUlh5dLWPKz-TcS9FP5gFhWVo-ZhU03Pn6P34OxHmXGWyQao18dQGqzgD4e9vY3rLhfcjVZJYNlWY2InsNwbYS-DnienPf1ws-miLeXxNKG3tFydoQzHwyOxG6Wc-HBfzL_hOvxINKQamvPasaYWl1LWznMps6elKCgKDc"},{"kty":"EC","crv":"P-521","kid":"c570888f","x":"AHNpXq0J7rikNRlwhaMYDD8LGVAVJzNJ-jEPksUIn2LB2LCdNRzfAhgbxdQcWT9ktlc9M1EhmTLccEqfnWdGL9G1","y":"AfHPUW3GYzzqbTczcYR0nYMVMFVrYsUxv4uiuSNV_XRN3Jf8zeYbbOLJv4S3bUytO7qHY8bfZxPxR9nn3BBTf5ol"}]}`)
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			var cache mockCache
			if tt.initMockCache != nil {
				tt.initMockCache(&cache)
				defer cache.AssertExpectations(t)
			}

			jwks := httptest.NewServer(tt.jwksHandler)
			defer jwks.Close()

			issuer := httptest.NewServer(tt.newIssuerHandler(jwks.URL))
			defer issuer.Close()

			client := Verifier{
				cache:  &cache,
				issuer: issuer.URL,
				client: http.DefaultClient,
			}

			fn, err := client.getKeyfunc(context.Background())
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.NotNil(t, fn)
		})
	}
}

func TestVerifier_getJWKSURI(t *testing.T) {
	cases := map[string]struct {
		handler http.HandlerFunc
		wantErr string
		wantURI string
	}{
		"non 200 response": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"status":500,"error":"internal server error"}`)
			},
			wantErr: `expected status code 200 but got status code 500 with data: {"status":500,"error":"internal server error"}`,
		},
		"malformed response body": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, `{"jwks_uri":1234}`)
			},
			wantErr: "json-decoding response body: json: cannot unmarshal number into Go struct field .jwks_uri of type string",
		},
		"success": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, `{"jwks_uri":"https://www.example.com"}`)
			},
			wantURI: "https://www.example.com",
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := Verifier{
				client:            server.Client(),
				issuer:            server.URL,
				wellKnownEndpoint: defaultWellKnownEndpoint,
			}

			gotURI, err := client.getJWKSURI(context.Background())
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.wantURI, gotURI, "got unexpected data")
		})
	}
}

func TestVerifier_getJWKS(t *testing.T) {
	cases := map[string]struct {
		handler  http.HandlerFunc
		wantErr  string
		wantData json.RawMessage
	}{
		"non 200 response": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"status":500,"error":"internal server error"}`)
			},
			wantErr: `expected status code 200 but got status code 500 with data: {"status":500,"error":"internal server error"}`,
		},
		"success": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, `{"foo":"bar"}`)
			},
			wantData: json.RawMessage(`{"foo":"bar"}`),
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := Verifier{
				client: server.Client(),
			}

			data, err := client.getJWKS(context.Background(), server.URL)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.wantData, data, "got unexpected data")
		})
	}
}

type mockCache struct {
	mock.Mock
}

func (m *mockCache) Get(_ context.Context, key string) (any, bool) {
	args := m.Called(key)
	return args.Get(0), args.Bool(1)
}

func (m *mockCache) Set(_ context.Context, key string, value any) {
	m.Called(key, value)
}
