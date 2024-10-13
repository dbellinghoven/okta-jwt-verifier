package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Rule receives the value of a claim from a parse JWT and returns a
// non-nil error if the value is not valid.
type Rule func(value any) error

// ClaimRule contains the JWT claim key and a function to verify the value
// of the claim.
type ClaimRule struct {
	Key  string
	Rule Rule
}

// WithAudienceRule will verify that the value of the 'aud' claim equals the
// given value.
func WithAudienceRule(wantAud string) ClaimRule {
	return WithCustomClaimExactMatchRule("aud", wantAud)
}

// WithClientIDRule will verify that the value of the 'cid' claim equals the
// given value.
func WithClientIDRule(wantCid string) ClaimRule {
	return WithCustomClaimExactMatchRule("cid", wantCid)
}

// WithIssuerRule will verify that the value of the 'iss' claim equals the
// issuer that the Verifier was initialized with.
func (j Verifier) WithIssuerRule() ClaimRule {
	return WithCustomClaimExactMatchRule("iss", j.issuer)
}

// WithExpirationRule returns a ClaimRule which will check if the value
// of the 'exp' claim is a timestamp is more than leeway seconds old, and if
// so it will return an error.
func (j Verifier) WithExpirationRule(leeway int) ClaimRule {
	return ClaimRule{
		Key: "exp",
		Rule: func(value any) error {
			ts, err := j.parseTimestamp(value)
			if err != nil {
				return err
			}

			if time.Now().UTC().Sub(ts) > time.Second*time.Duration(leeway) {
				return errors.New("token is expired")
			}

			return nil
		},
	}
}

// WithIssuedAtRule returns a ClaimRule which will check if the value
// of the 'iss' claim is a timestamp is more than leeway seconds in the future,
// and if so it will return an error.
func (j Verifier) WithIssuedAtRule(leeway int) ClaimRule {
	return ClaimRule{
		Key: "iss",
		Rule: func(value any) error {
			ts, err := j.parseTimestamp(value)
			if err != nil {
				return err
			}

			if time.Now().UTC().Sub(ts) < time.Second*time.Duration(leeway) {
				return errors.New("token was issued in the future")
			}

			return nil
		},
	}
}

// WithCustomClaimExactMatchRule will check that the value of the given
// claim equals the given value exactly.
func WithCustomClaimExactMatchRule[T comparable](claim string, wantValue T) ClaimRule {
	return ClaimRule{
		Key: claim,
		Rule: func(value any) error {
			got, ok := value.(T)
			if !ok {
				return fmt.Errorf("expected a %T but got a %T", got, value)
			}

			if wantValue != got {
				return fmt.Errorf("expected '%v' but got '%v'", wantValue, got)
			}

			return nil
		},
	}
}

// WithCustomClaimContainsRule will check that wantValue is in the claim,
// whose value should be an array.
func WithCustomClaimContainsRule[T comparable](claim string, wantValue T) ClaimRule {
	return ClaimRule{
		Key: claim,
		Rule: func(value any) error {
			raw, ok := value.([]any)
			if !ok {
				return fmt.Errorf("expected an array but got a %T", value)
			}

			for _, v := range raw {
				claim, ok := v.(T)
				if !ok {
					return fmt.Errorf("value of array element is not a %T", claim)
				}

				if claim == wantValue {
					return nil
				}
			}

			return fmt.Errorf("value '%v' not present in claim", wantValue)
		},
	}
}

func (j Verifier) parseTimestamp(value any) (time.Time, error) {
	if j.useJSONNumber {
		exp, ok := value.(json.Number)
		if !ok {
			return time.Time{}, fmt.Errorf("expected a %T but got a %T", exp, value)
		}

		unixTime, err := exp.Int64()
		if err != nil {
			return time.Time{}, err
		}

		return time.Unix(unixTime, 0).UTC(), nil
	}

	exp, ok := value.(float64)
	if !ok {
		return time.Time{}, fmt.Errorf("expected a %T but got a %T", exp, value)
	}

	return time.Unix(int64(exp), 0).UTC(), nil
}
