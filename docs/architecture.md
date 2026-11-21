# Architecture

GTG separates low-level cryptographic primitives from protocol encoding, transport helpers, bounded client state, and application-oriented helpers.

1. `core` owns low-level cryptographic primitives and packet helpers.
2. `tl` owns dynamic schema construction and bounded encoding and decoding.
3. `internal/tlgen` owns generated schema declarations and typed wrappers.
4. `client`, `updates`, `entities`, `auth`, and `api` provide constrained higher-level foundations.

The package graph is intentionally layered. Callers should use package-specific APIs rather than reaching into internal packages.
