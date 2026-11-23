# Changelog

## 0.2.0

### Fixed

- Preserve host-only cookie scope across browser and inline sources, including during deduplication. Require a valid origin before reading cookies and exclude partitioned cookies and Firefox container cookies. If an inline source contains isolated cookies, try other inline sources before returning an empty result. ([Cookie isolation](https://github.com/steipete/sweet-cookie/commit/2d09b9f), [opaque URLs](https://github.com/steipete/sweet-cookie/pull/32))
- Read Firefox schema 16+ expiries in milliseconds and return Unix seconds. Omit expiry timestamps past year 9999 and resolve renamed databases and directories named `cookies.sqlite`. ([Firefox expiry bounds](https://github.com/steipete/sweet-cookie/pull/22), [schema and path fixes](https://github.com/steipete/sweet-cookie/pull/70))
- Verify Chromium schema 24+ host bindings before returning decrypted cookies. Warn when a binding fails verification or a `v20` App-Bound cookie cannot be decrypted. ([Host verification](https://github.com/steipete/sweet-cookie/pull/70), [App-Bound diagnostics](https://github.com/steipete/sweet-cookie/pull/24))
- Keep Chromium and Firefox SQLite queries within the expression-depth limit when reading large origin lists. ([Large origin lists](https://github.com/steipete/sweet-cookie/pull/74))
- Honor caller timeouts for Linux keyring and Windows DPAPI helpers, ignore relative Linux XDG configuration roots, and surface permission errors during Chromium profile discovery. ([Platform fixes](https://github.com/steipete/sweet-cookie/pull/70), [discovery permissions](https://github.com/steipete/sweet-cookie/pull/37))

### Added

- Select multiple or all discovered Chrome, Edge, and Firefox profiles in the Rust API and CLI. Select Chromium profiles by display name and supply multiple explicit Safari cookie files. ([Multi-profile support](https://github.com/steipete/sweet-cookie/pull/30))
- Discover modern Linux Firefox and Chromium-family layouts, including the supported Snap and Flatpak roots. Select Brave or Chromium on macOS and Linux, and Arc or Dia on macOS. Keychain or keyring selection follows the requested browser. ([Linux discovery](https://github.com/steipete/sweet-cookie/pull/47), [macOS targeting](https://github.com/steipete/sweet-cookie/pull/2), [Dia support](https://github.com/steipete/sweet-cookie/commit/e735aed))

### Rust API changes

- `Cookie` struct literals now require `host_only: Option<bool>`, serialized as `hostOnly` when present. Existing JSON payloads can omit it.
- Use `GetCookiesOptions::new()` and the builder methods for profile selection and Chromium targeting. Struct literals for the public options types need the new fields.
- The low-level Chromium decryptors take an optional expected host key and return a typed error. Pass `None` for older cookie database schemas.

## 0.1.1 - 2026-02-17

- Record the TypeScript and Swift upstream revisions used by the Rust port.

## 0.1.0 - 2026-02-09

- Initial library and CLI release with inline cookie input and Chrome, Edge, Firefox, and Safari providers.
