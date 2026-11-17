# `lmsaml` Architecture, SAML 2.0 IdP/SP Server & Standard `lmcode` Interfaces

## Summary

`lmsaml` (`cmd/lmsaml`) is a pure-Go single-binary SAML 2.0 Identity Provider (IdP), Service Provider (SP), REST server, and `lmcode-go` host built on `crewjam/saml`:
1. **Dual-Mode SAML 2.0 Server + REST API**:
   - Ephemeral RSA-2048 X.509 self-signed certificate generation, `/idp/metadata`, `/idp/sso`, `/sp/metadata`, `/sp/acs`, `/api/ping`, `/api/users`, `/api/services`, `/api/authn-request`, `/api/issue-assertion`, and `/api/validate-assertion`.
2. **Embedded `lmcode-go` Host (`cmd/lmsaml/host.go`, `schema/lmsaml.dsl.json`)**:
   - Exposes `saml` context (`ping`, `idp_metadata`, `sp_metadata`, `put_user`, `get_user`, `list_users`, `delete_user`, `authn_request`, `issue_assertion`, `validate_assertion`) and the 226-signature `lmcode_std_v3` catalog (`RestGet`..`RestOptions`, `RestHandler`, `CliCommand`, `CliOption`, `rest_config`, `rest_serve`, `rest_cli`).
   - Verified in `.github/workflows/ci.yml` (5-platform build & release + integration test with `lmconn saml` and `lmcurl`).
