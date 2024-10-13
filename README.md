# okta-jwt-verifier

[![Test](https://github.com/dbellinghoven/okta-jwt-verifier/actions/workflows/test.yml/badge.svg)](https://github.com/dbellinghoven/okta-jwt-verifier/actions/workflows/test.yml)
[![GoDoc](https://godoc.org/github.com/dbellinghoven/okta-jwt-verifier?status.png)](http://godoc.org/github.com/dbellinghoven/okta-jwt-verifier)
[![Go Report](https://goreportcard.com/badge/github.com/dbellinghoven/okta-jwt-verifier)](https://goreportcard.com/report/github.com/dbellinghoven/okta-jwt-verifier)

A context-aware, highly-customizable alternative to
[okta-jwt-verifier](https://github.com/okta/okta-jwt-verifier-golang) which
will parse Okta-issued JWT tokens and verify its claims.

## Why use this instead of [the official Okta JWT verifier Go library](https://github.com/okta/okta-jwt-verifier-golang)?

### Context awareness

All methods that perform network calls receive a context, and they will pass
the context to add downstream calls that also receive a context. This ensures
that the context is honored, and also enables instrumentation of telemetry,
such as DataDog or OpenTelemetry.

### Support for custom claim validation rules

The official Okta library only supports validating a specific set of claims. It
does not support validating any custom claims outside of these 

Intuitive interface

### Simplicity, readability, idiomatic-ness

### All-at-once claim validation

Despite allowing you to validate multiple claims, the 
