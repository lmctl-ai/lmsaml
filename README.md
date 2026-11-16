# lmsaml — Single-Binary SAML 2.0 Identity Provider, Service Provider, REST API & `lmcode` Host

`lmsaml` is a pure-Go (`CGO_ENABLED=0`), zero-dependency single-binary SAML 2.0 server and `lmcode` host built on [`crewjam/saml`](https://github.com/crewjam/saml) and [`lmctl-ai/lmcode-go`](https://github.com/lmctl-ai/lmcode-go).

## Key Capabilities

1. **Single-Binary Turnkey SAML 2.0 IdP & SP (`./lmsaml --port 8080 --rest-port 8081`)**:
   - Automatically generates RSA-2048 X.509 signing keypairs/certificates for both the Identity Provider (IdP) and built-in Service Provider (SP).
   - Seeds the initial administrator account (`admin` / `admin`) and pre-registers the built-in Service Provider (`sp-default`) with the IdP.
   - Exposes standard SAML 2.0 endpoints:
     - `GET /idp/metadata` & `GET /metadata`: IdP `EntityDescriptor` XML (`application/samlmetadata+xml`)
     - `GET|POST /idp/sso` & `/sso`: SAML 2.0 Single Sign-On (HTTP-Redirect and HTTP-POST bindings)
     - `GET|POST /idp/slo` & `/slo`: SAML 2.0 Single Logout
     - `GET|POST /idp/login` & `/login`: Interactive SAML IdP Login form
     - `GET /sp/metadata`: Built-in SP `EntityDescriptor` XML
     - `POST /sp/acs`: Built-in SP Assertion Consumer Service (ACS)
     - `GET /sp/hello`: Protected SP resource triggering SP-initiated `<samlp:AuthnRequest>` redirect to `/idp/sso`

2. **Integrated HTTP REST API**:
   - `GET /` and `GET /ping`: Health check (`{"ok":true,"result":"PONG","service":"lmsaml"}`)
   - `GET /users`, `PUT /users/{id}`, `GET /users/{id}`, `DELETE /users/{id}`: JSON user directory CRUD
   - `GET /services`, `PUT /services/{id}`, `GET /services/{id}`, `DELETE /services/{id}`: SAML SP metadata management
   - `POST /authn`: Verify user credentials against `bcrypt` store
   - `POST /assertion`: Issue a cryptographically signed SAML 2.0 `<samlp:Response>` & `<saml:Assertion>` (`RSA-SHA256` + XML Exclusive C14N)
   - `POST /verify`: Cryptographically verify a SAML 2.0 `<samlp:Response>` (base64 or raw XML) against the IdP certificate, audience, and validity window

3. **Native `lmcode` Host (`context saml: Saml`, `Batch`, and `lmcode_std_v3`)**:
   - Embeds `github.com/lmctl-ai/lmcode-go` with all 226 `lmcode_std_v3` signatures and 10 standard REST/CLI interfaces (`RestGet`, `RestPost`, `RestHandler`, `CliCommand`, `CliOption`, `rest_config`, `rest_serve`, `rest_cli`).
   - Supports `--version`, `--lmcode-schema [--json]`, `--lmcode-signatures`, and `--lmcode <file.dslb>`.

4. **Client Support in `lmconn` and `lmcurl`**:
   - `lmconn saml <ping|metadata|sp-metadata|users|user-get|user-add|user-del|authn|assertion|verify>`
   - `lmcurl` HTTP/REST & XML assertion testing

## Building & Running Tests

```bash
CGO_ENABLED=0 go build -trimpath -o lmsaml ./cmd/lmsaml
./test.sh
```
