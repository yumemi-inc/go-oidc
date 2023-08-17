# go-oidc

Low-level and strongly typed library for OpenID Connect / OAuth 2.0 client or server written in Go.

> **Warning**  
> This project is heavily in progress. All interfaces may subject to change. DO NOT USE IN PRODUCTION.

> **Warning**  
> This is not an official product of YUMEMI Inc.


## Features

### OAuth 2.0

- Authorization Grant Types
  - [x] Authorization Code Grant
  - [ ] Implicit Grant
  - [ ] Resource Owner Password Credentials Grant
  - [ ] Client Credentials Grant
- Extensions
  - [x] Proof Key for Code Exchange by OAuth Public Clients (PKCE)
  - [ ] Assertion Framework for OAuth 2.0 Client Authentication and
    Authorization Grants

### OpenID Connect 1.0

- Authentication Flows
  - [x] Authorization Code Flow
  - [ ] Implicit Flow
  - [ ] Hybrid Flow
- Claims
  - [x] Standard Claims
  - [x] Claims Languages and Scripts
  - [x] Userinfo Endpoint
  - [x] Requesting Claims using Scope Values
  - [x] Requesting Claims using the "claims" Request Parameter
  - Claim Types
    - [x] Normal Claims
    - [ ] Aggregated Claims
    - [ ] Distributed Claims
- Passing Request Parameters as JWTs
  - [x] Passing a Request Object by Value (request)
  - [x] Passing a Request Object by Reference (request_uri)
- Client Authentication
  - [x] client_secret_basic
  - [x] client_secret_post
  - [ ] client_secret_jwt
  - [ ] private_key_jwt
  - [x] none
- Signatures and Encryption
  - [x] Signing
  - [x] Encryption
- Misc
  - [ ] Initiating Login from a Third Party
  - [ ] Self-Issued OpenID Provider
  - [ ] Pairwise Subject Identifier
  - [ ] Offline Access
  - [x] Using Refresh Tokens
- Extensions
  - OpenID Connect Discovery
    - [ ] WebFinger
    - [x] Provider Metadata
  - [x] OpenID Connect RP-Initiated Logout
  - [ ] OpenID Connect Front-Channel Logout
  - [ ] OpenID Connect Back-Channel Logout
  - [ ] OpenID Connect Dynamic Client Registration
  - [ ] OpenID Connect Session Management
  - [ ] OpenID Provider Authentication Policy Extension

### Examples

- [x] Server (OpenID Provider)
- [ ] Client (Relying Party)
