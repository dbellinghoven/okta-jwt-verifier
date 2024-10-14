# okta-jwt-verifier

[![Test](https://github.com/dbellinghoven/okta-jwt-verifier/actions/workflows/test.yml/badge.svg)](https://github.com/dbellinghoven/okta-jwt-verifier/actions/workflows/test.yml)
[![GoDoc](https://godoc.org/github.com/dbellinghoven/okta-jwt-verifier?status.png)](http://godoc.org/github.com/dbellinghoven/okta-jwt-verifier)
[![Go Report](https://goreportcard.com/badge/github.com/dbellinghoven/okta-jwt-verifier)](https://goreportcard.com/report/github.com/dbellinghoven/okta-jwt-verifier)

A context-aware, highly-customizable Golang client for parsing and validating
JSON Web Tokens (JWTs) issued by Okta. Intended as an alternative to
[okta-jwt-verifier](https://github.com/okta/okta-jwt-verifier-golang).

## Why use this instead of [the official Okta JWT verifier Go library](https://github.com/okta/okta-jwt-verifier-golang)?

### Context awareness

Unlike the official library, which is not context-aware, all network-call
methods in this library accept a context and pass it through to downstream
calls. This ensures the context is consistently honored and enables seamless
integration with telemetry tools like DataDog or OpenTelemetry.

### Support for custom claim validation rules

The official library only supports validation of a predefined set of claims
with rigid, exact-match rules, and does not allow customization or validation
of custom claims. In contrast, this library enables validation of any claim an
offers flexible, customizable validation rules.

### Simplicity, readability, idiomatic-ness

The official library has a clunky, non-idiomatic interface that's awkward to
use. In contrast, this library is designed to be highly readable, intuitive,
and follows idiomatic conventions for a smooth developer experience.

### All-at-once claim validation

Unlike the official library, which validates claims one at a time, this library
validates all claims at once according to the provided rules and gives
comprehensive feedback on any issues in a single pass.

## Compatibilty

The official Okta JWT verifier library has to core functions:
`VerifyAccessToken()` and `VerifyIdToken()`. These basically work the same way,
where they parse the JWT and a set of claims according to some built-in rules.
By contrast, the verifier in this library has just one method:
`ParseAndVerify()`. By default, it **only parses the token**, and will **only
validate the claims according to the claim validation rules that are passed
into it**. This means that the claims that you wish to validate for a JWT must
be explicitly provided, but it also means that it makes no assumptions about
which claims you want to verify and gives you the power to customize your claim
validation logic.

## Examples

### Basic usage

The most common usage of this library will be to parse Okta-issued JWTs and
verify certain claims according to specific rules, such as ensuring the
value of the audience and issuer claims match some expected values. This
library provides a number of [rules](https://pkg.go.dev/github.com/dbellinghoven/okta-jwt-verifier#ClaimRule)
to verify some common claims:

* [Audience](https://pkg.go.dev/github.com/dbellinghoven/okta-jwt-verifier#WithAudienceRule) (`aud`)
* [Issuer](https://pkg.go.dev/github.com/dbellinghoven/okta-jwt-verifier#Verifier.WithIssuerRule) (`iss`)
* [Expiration](https://pkg.go.dev/github.com/dbellinghoven/okta-jwt-verifier#Verifier.WithExpirationRule) (`exp`)
* [Issued at](https://pkg.go.dev/github.com/dbellinghoven/okta-jwt-verifier#Verifier.WithIssuedAtRule) (`iat`)
* [Client ID](https://pkg.go.dev/github.com/dbellinghoven/okta-jwt-verifier#Verifier.WithClientIDRule) (`cid`)

```go
import (
    "context"

    verifier "github.com/dbellinghoven/okta-jwt-verifier"
)

func main() {
    ctx := context.Background()

    issuer := "https://login.example.com"
    v := verifier.New(issuer)

    // Parse the JWT and verify that (1) the value of the 'aud' claim is
    // 'my-audience', (2) the value of the 'iss' claim is
    // 'https://login.example.com', and (3) the value of 'exp' is no more than
    // 100 seconds in the past.
    token, err := v.ParseAndVerify(
        ctx,
        "${JWT}",
        verifier.WithAudienceRule("my-audience"),
        v.WithIssuerRule(),
        v.WithExpirationRule(100),
    )
    // ...
}
```

### Custom claim verification rules

For any claims that you want to verify that is not covered by any of the
`ClaimRule` generators provided in this library, you can create a custom rule.

For instance, let's imagine that I want to validate a JWT to ensure that:
1. It possesses a `role` claim whose value is a string, and that the value of
the claim is `writer` or `admin`.
2. It possesses an `entitlements` claim that is a value of strings and that it
contains at least the value `"api"`.

We could express these rules by building two new `ClaimRule`s like so.

```go
import (
    "context"

    verifier "github.com/dbellinghoven/okta-jwt-verifier"
)

func main() {
    ctx := context.Background()

    issuer := "https://login.example.com"
    v := verifier.New(issuer)

    roleRule := verifier.ClaimRule{
        Key: "role",
        Rule: func(value any) error {
            got, ok := value.(string)
            if !ok {
                return fmt.Errorf("expected a %T but got a %T", got, value)
            }

            for _, want := range []string{"writer", "admin"} {
                if want == got {
                    return nil
                }
            }

            return errors.New("does not equal any expected values")
        },
    }

    entitlementRule := verifier.ClaimRule{
        Key: "entitlements"
        Rule: func(value any) error {
            rawValues, ok := value.([]any)
            if !ok {
                return fmt.Errorf("expected a %T but got a %T", got, value)
            }

            for _, rawValue := range rawValues {
                got, ok := rawValue.(string)
                if !ok {
                    return fmt.Errorf("expected values of claim to be an array of strings but got an array of %T", rawValue)
                }

                if got == "api" {
                    return nil
                }
            }

            return errors.New("does not contain the expected value")
        },
    }

    token, err := v.ParseAndVerify(ctx, "${JWT}", roleRule, entitlementRule)
    if err != nil {
        panic(err)
    }
    // ...
}
```

Using the example above, if the value of `$JWT` was a JWT whose claims looked
something like the JSON blob below then `ParseAndVerify()` would return an
error indicating that validation failed because the value of the `role` claim
is not either `"writer"` or `"admin"` (whereas the other rule validating the
`entitlements` claim would pass because it contains the target value `"api"`).

```json
{
  // ...
  "role": "reader",
  "entitlements": [
    "ui",
    "api"
  ],
  // ...
}
```
