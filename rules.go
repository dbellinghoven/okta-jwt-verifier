package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Rule receives the value of a claim from a parse JWT and returns a non-nil
// error if the value is not valid.
//
// Note that during ParseAndVerify() the claims are unmarshalled as a
// map[string]any, so the value that is passed into the rule will follow the
// same rules. For instance, if the value of the claim to be validated is a
// string, then value will be a string. If the value of the claim is an array
// of strings, then value will be an []any. If the value of the claim is
// another object, then value will be a map[string]any.
type Rule func(value any) error

// ClaimRule contains the JWT claim key and a function to verify the value
// of the claim.
type ClaimRule struct {
	Key  string
	Rule Rule
}

// WithIssuerRule will verify that the value of the 'iss' claim equals the
// given value.
func WithIssuerRule(wantIss string) ClaimRule {
	return WithCustomClaimExactMatchRule("iss", wantIss)
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

// WithExpirationRule returns a ClaimRule which will check if the value
// of the 'exp' claim is a timestamp is more than leeway seconds old, and if
// so it will return an error.
//
// This should only be called if the [WithJSONNumber] is not used with
// [Verifier.ParseAndVerify].
func WithExpirationRule(leeway int) ClaimRule {
	return withTimestampRule("exp", leeway, false, time.Since, "token is expired")
}

// WithExpirationRuleJSONNumber returns a ClaimRule which will check if the
// value of the 'exp' claim is a timestamp is more than leeway seconds old, and
// if so it will return an error.
//
// This should only be called if the [WithJSONNumber] is used with
// [Verifier.ParseAndVerify].
func WithExpirationRuleJSONNumber(leeway int) ClaimRule {
	return withTimestampRule("exp", leeway, true, time.Since, "token is expired")
}

// WithIssuedAtRule returns a ClaimRule which will check if the value
// of the 'iat' claim is a timestamp is more than leeway seconds in the future,
// and if so it will return an error.
//
// This should only be called if the [WithJSONNumber] is not used with
// [Verifier.ParseAndVerify].
func WithIssuedAtRule(leeway int) ClaimRule {
	return withTimestampRule("iat", leeway, false, time.Since, "token was issued in the future")
}

// WithIssuedAtRuleJSONNumber returns a ClaimRule which will check if the value
// of the 'iat' claim is a timestamp is more than leeway seconds in the future,
// and if so it will return an error.
//
// This should only be called if the [WithJSONNumber] is used with
// [Verifier.ParseAndVerify].
func WithIssuedAtRuleJSONNumber(leeway int) ClaimRule {
	return withTimestampRule("iat", leeway, true, time.Since, "token was issued in the future")
}

// WithIssuerRule will verify that the value of the 'iss' claim equals the
// issuer that the Verifier was initialized with.
func (j Verifier) WithIssuerRule() ClaimRule {
	return WithIssuerRule(j.issuer)
}

// WithExpirationRule returns a ClaimRule which will check if the value
// of the 'exp' claim is a timestamp is more than leeway seconds old, and if
// so it will return an error.
func (j Verifier) WithExpirationRule(leeway int) ClaimRule {
	return withTimestampRule("exp", leeway, j.useJSONNumber, time.Since, "token is expired")
}

// WithIssuedAtRule returns a ClaimRule which will check if the value
// of the 'iat' claim is a timestamp is more than leeway seconds in the future,
// and if so it will return an error.
func (j Verifier) WithIssuedAtRule(leeway int) ClaimRule {
	return withTimestampRule("iat", leeway, j.useJSONNumber, time.Until, "token was issued in the future")
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

// WithCustomClaimContainsRule will check that all of the values in wantValue
// are presen in the claim, whose value should be an array of the same type.
func WithCustomClaimContainsRule[T comparable](claim string, wantValues []T) ClaimRule {
	return ClaimRule{
		Key: claim,
		Rule: func(value any) error {
			raw, ok := value.([]any)
			if !ok {
				return fmt.Errorf("expected an array but got a %T", value)
			}

			gotValuesSet := make(map[T]struct{})

			for _, v := range raw {
				claim, ok := v.(T)
				if !ok {
					return fmt.Errorf("value of array element is not a %T", claim)
				}

				gotValuesSet[claim] = struct{}{}
			}

			missingValues := make([]T, 0)
			for _, wantValue := range wantValues {
				if _, ok := gotValuesSet[wantValue]; !ok {
					missingValues = append(missingValues, wantValue)
				}
			}

			if len(missingValues) == 0 {
				return nil
			}

			var builder strings.Builder
			builder.WriteString(fmt.Sprintf("'%v'", missingValues[0]))
			for _, value := range missingValues[1:] {
				builder.WriteString(fmt.Sprintf(", '%v'", value))
			}

			return fmt.Errorf("missing value(s): %s", builder.String())
		},
	}
}

func withTimestampRule(
	claim string,
	leeway int,
	useJSONNumber bool,
	comparer func(time.Time) time.Duration,
	errMsg string,
) ClaimRule {
	return ClaimRule{
		Key: claim,
		Rule: func(value any) error {
			ts, err := parseTimestamp(value, useJSONNumber)
			if err != nil {
				return err
			}

			if comparer(ts) > time.Second*time.Duration(leeway) {
				return errors.New(errMsg)
			}

			return nil
		},
	}
}

func parseTimestamp(value any, useJSONNumber bool) (time.Time, error) {
	if useJSONNumber {
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
