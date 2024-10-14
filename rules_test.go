package verifier

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifier_WithIssuedAtRule(t *testing.T) {
	testIssuer := "https://www.example.com"
	testTimestamp := time.Now().UTC()

	cases := map[string]struct {
		claims  map[string]any
		leeway  int
		value   any
		wantErr string
	}{
		"invalid timestamp": {
			claims: map[string]any{
				"iat": "foobar",
			},
			wantErr: "expected a float64 but got a string",
		},
		"no leeway/fails validation": {
			claims: map[string]any{
				"iat": float64(testTimestamp.Add(30 * time.Second).Unix()),
			},
			wantErr: "token was issued in the future",
		},
		"with leeway/passes validation": {
			claims: map[string]any{
				"iat": float64(testTimestamp.Add(30 * time.Second).Unix()),
			},
			leeway: 60,
		},
		"no leeway/passes validation": {
			claims: map[string]any{
				"iat": float64(testTimestamp.Unix()),
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			verifier := New(testIssuer)
			verifier.now = func() time.Time {
				return testTimestamp
			}

			rule := verifier.WithIssuedAtRule(tt.leeway)
			require.Equal(t, rule.Key, "iat")

			err := rule.Rule(tt.claims[rule.Key])
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestVerifier_WithExpirationRule(t *testing.T) {
	testIssuer := "https://www.example.com"
	testTimestamp := time.Now().UTC()

	cases := map[string]struct {
		claims  map[string]any
		leeway  int
		value   any
		wantErr string
	}{
		"invalid timestamp": {
			claims: map[string]any{
				"exp": "foobar",
			},
			wantErr: "expected a float64 but got a string",
		},
		"no leeway/fails validation": {
			claims: map[string]any{
				"exp": float64(testTimestamp.Add(-30 * time.Second).Unix()),
			},
			wantErr: "token is expired",
		},
		"with leeway/passes validation": {
			claims: map[string]any{
				"exp": float64(testTimestamp.Add(-30 * time.Second).Unix()),
			},
			leeway: 60,
		},
		"no leeway/passes validation": {
			claims: map[string]any{
				"exp": float64(testTimestamp.Add(30 * time.Second).Unix()),
			},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			verifier := New(testIssuer)
			verifier.now = func() time.Time {
				return testTimestamp
			}

			rule := verifier.WithExpirationRule(tt.leeway)
			require.Equal(t, rule.Key, "exp")

			err := rule.Rule(tt.claims[rule.Key])
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestWithCustomClaimExactMatchRule(t *testing.T) {
	cases := map[string]struct {
		claim     string
		claims    map[string]any
		wantValue string
		wantErr   string
	}{
		"wrong type": {
			claim: "foo",
			claims: map[string]any{
				"foo": []any{"bar"},
			},
			wantErr: "expected a string but got a []interface {}",
		},
		"fails validation": {
			claim: "foo",
			claims: map[string]any{
				"foo": "bar",
			},
			wantValue: "hello",
			wantErr:   "expected 'hello' but got 'bar'",
		},
		"passes validation": {
			claim: "foo",
			claims: map[string]any{
				"foo": "bar",
			},
			wantValue: "bar",
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			rule := WithCustomClaimExactMatchRule(tt.claim, tt.wantValue)
			require.Equal(t, rule.Key, tt.claim)

			err := rule.Rule(tt.claims[rule.Key])
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestWithCustomClaimContainsRule(t *testing.T) {
	cases := map[string]struct {
		claim     string
		claims    map[string]any
		wantValue string
		wantErr   string
	}{
		"wrong type": {
			claim: "foo",
			claims: map[string]any{
				"foo": "bar",
			},
			wantErr: "expected an array but got a string",
		},
		"fails validation": {
			claim: "foo",
			claims: map[string]any{
				"foo": []any{"bar", "hello"},
			},
			wantValue: "world",
			wantErr:   "value 'world' not present in claim",
		},
		"passes validation": {
			claim: "foo",
			claims: map[string]any{
				"foo": []any{"bar", "hello"},
			},
			wantValue: "bar",
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			rule := WithCustomClaimContainsRule(tt.claim, tt.wantValue)
			require.Equal(t, rule.Key, tt.claim)

			err := rule.Rule(tt.claims[rule.Key])
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
