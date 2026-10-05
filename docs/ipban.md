# Downloaded IP blocklist

`ipban` is an optional, global IP-only block. It can run alongside the normal
definition/ban policy or on its own. For a standalone installation, add these
directives to the global Ferron configuration block:

```text
ipban_mode true
ipban_log "/var/log/ferron/ipban.log"
# Optional overrides:
# ipban_url "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-14d.ipv4"
# ipban_interval "24h"
```

`ipban_mode` defaults to false. The default URL is the AbuseIPDB s100-14d
IPv4 feed above; the default refresh interval is 24 hours (accepted range:
1 minute to 30 days). The log path is required when enabled. All four
directives are global-only. With an existing definition/ban configuration,
keep its usual required settings; standalone mode needs none of those settings.

The first download begins in the background after startup, so an installation
with no successful fetch initially has an empty list. Updates are installed
only when the full HTTPS download and parsing succeed. Failures keep the last
good list and retry after the shorter of five minutes and the configured
interval. Downloads are limited to 16 MiB and 250,000 entries. Blank lines,
`#` comments, and trailing `#` comments are supported; any malformed address
invalidates the entire update. No copy is cached between restarts.

An available definitions allowlist takes precedence, followed by ipban, then
the normal definition and extension-ban checks. A listed visitor receives a
403 response with `Retry-After: 60`. With `proxied_by cloudflare`, the check
uses the trusted `CF-Connecting-IP` visitor address, while the connecting peer
appears only in the log's `proxy_ip` field. The dedicated log uses the same
Apache combined-style format as `matched_log`, with `ipban` as its final
field. Its bounded asynchronous writer is best-effort and can drop entries
under sustained load.
