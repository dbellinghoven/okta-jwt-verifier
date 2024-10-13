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

// NewAudienceRule will verify that the value of the 'aud' claim equals the
// given value.
func NewAudienceRule(wantAud string) ClaimRule {
	return NewCustomClaimExactMatchRule("aud", wantAud)
}

// NewClientIDRule will verify that the value of the 'cid' claim equals the
// given value.
func NewClientIDRule(wantCid string) ClaimRule {
	return NewCustomClaimExactMatchRule("cid", wantCid)
}

// NewIssuerRule will verify that the value of the 'iss' claim equals the
// issuer that the Verifier was initialized with.
func (j Verifier) NewIssuerRule() ClaimRule {
	return NewCustomClaimExactMatchRule("iss", j.issuer)
}

// NewExpirationRule returns a ClaimRule which will check if the value
// of the 'exp' claim is a timestamp is more than leeway seconds old, and if
// so it will return an error.
func (j Verifier) NewExpirationRule(leeway int) ClaimRule {
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

// NewIssuedAtRule returns a ClaimRule which will check if the value
// of the 'iss' claim is a timestamp is more than leeway seconds in the future,
// and if so it will return an error.
func (j Verifier) NewIssuedAtRule(leeway int) ClaimRule {
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

// NewCustomClaimExactMatchRule will check that the value of the given
// claim equals the given value exactly.
func NewCustomClaimExactMatchRule[T comparable](claim string, wantValue T) ClaimRule {
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

// NewCustomClaimContainsRule will check that wantValue is in the claim,
// whose value should be an array.
func NewCustomClaimContainsRule[T comparable](claim string, wantValue T) ClaimRule {
	return ClaimRule{
		Key: claim,
		Rule: func(value any) error {
			claims, ok := value.([]T)
			if !ok {
				return fmt.Errorf("expected a %T but got a %T", claims, value)
			}

			for _, claim := range claims {
				if claim == wantValue {
					return nil
				}
			}

			return fmt.Errorf("value '%s' not present in claim", claim)
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
