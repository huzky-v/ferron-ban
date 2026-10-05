`snapshot-v1.yml` is the canonical definition snapshot integration fixture. It
loads `attack-definitions-snapshot-v1.sql` directly and covers current positive
and negative matching behavior. Update this fixture and SQL together; no Rust
changes are needed.

Each case supplies `request.target` and may set `request.method`, `host`, `user_agent`, `headers` (pairs), `request_bytes`, or `body_sha256`. Omitted request fields use the test defaults. Use `matched: [name, ...]` for required matches (other definitions may also match), `selected: []` or `selected: [name]` for the selected template definition, and `no_match: true` to require no match at all.
