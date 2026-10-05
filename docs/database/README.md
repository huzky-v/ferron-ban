# Attack definition updates

The application loads SQLite definitions read-only at startup. Definition
updates are published as one canonical snapshot at
`attack-definitions-snapshot-v1.sql`. For an existing definitions database,
build a new database from that snapshot and deploy it in place of the previous
database; do not apply the snapshot to an existing database.

```sh
rm -f definitions.sqlite
sqlite3 -bail definitions.sqlite '.read docs/database/attack-definitions-snapshot-v1.sql'
cargo run -q -p ferron-abuse-protection --bin abuse-definitions-init -- definitions.sqlite
```

The snapshot has schema version 2 and definition snapshot version 2. Schema
initialization also migrates existing v1-schema databases to v2, but only when
called explicitly; the server itself never modifies the database. When using
`definitions_bundle`, build a new bundle containing the snapshot database and
matching responses.

The canonical snapshot contains the latest accumulated rules: secret-file
decoys and ban-only probes, including the latest snapshot v2 additions. Deploy
every matching `honeypot-responses/id-leak-*.yaml` file alongside the database
(or in the same bundle) before enabling honeypot mode. Common application routes such
as `/admin`, `/db`, `/login`, `/info.php`, the service-account CA certificate,
and arbitrary PHP filenames remain unmatched. Restart Ferron after replacing
the definitions database or bundle.

Snapshot v2 adds honeypot decoys for Azure CLI tokens, GitHub CLI, DigitalOcean,
OpenStack, rclone, Lambda Cloud, and LiteLLM credentials. It adds narrow
ban-only probes for Ansible inventory/config files, deployment manifests, and
the observed router command-injection and language traversal query signatures.
It also extends Kubernetes and AWS config matches, adds the observed Staging
appsettings and appliance paths, and factors the phpMyAdmin rule into shorter
alternative blocks without widening generic admin routes.

The canonical snapshot classifies WordPress core routes as `wp_ban`. The policy
skips these definitions on sites with `wordpress_site true`, and ignores `php`
in that site's effective `ban_extensions` (other extensions remain active). `wp-config.php`
and its backup variants stay `id_leak` on every site. On a non-WordPress site,
WordPress hits use the normal configured ban response and appear as `wp-ban`
in `matched_log`.

The `no_log` type marks harmless requests without banning them. When it matches,
the request does not appear in either abuse `matched_log` or unmatched-banned
`audit_log`; an already-banned IP still receives the active-ban response.
The canonical snapshot contains one such rule for `/favicon.ico`.

Rules use normalized, once-decoded paths and component boundaries, including
subdirectory installations. Generic paths such as `/index.php`, `/readme.html`,
and `/license.txt` are deliberately not WordPress probe rules. Plugin- and
theme-specific vulnerabilities require their own narrow definitions.

## Abuse logs

`matched_log` uses Apache combined format with three additional quoted fields:
the connecting `proxy_ip` (`-` for direct requests), the request Host (or
resolved hostname when the Host header is absent), and the matching rule
name(s), or `extban`. Host and rule are escaped for single-line logging; a
missing host is `-`. The first IP remains the visitor IP used for bans.

Unmatched requests from already-banned IPs appear in the NDJSON `audit_log`.
`triggering_definition_ids` and `triggering_attack_types` describe the rule(s)
that originally caused the ban, not matches on the logged request.
`content_length_bytes` is the declared Content-Length, or 0 if it is absent or
invalid; it is not a measured body size. `definition_snapshot_version` is the
snapshot used to evaluate the logged request.
With `proxied_by cloudflare`, `ip` is the visitor address from CF-Connecting-IP
and `proxy_ip` is the Cloudflare connecting peer (omitted for direct requests).
Cloudflare's IPv4 and IPv6 ranges are fetched over HTTPS once at startup from
https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6; an
unavailable or invalid list prevents startup. Restart to refresh the ranges.
The default `proxied_by none` preserves direct-peer behavior. Do not combine
`proxied_by cloudflare` with Ferron's `client_ip_from_header`. Cloudflare must
connect directly to Ferron for its peer address to match the published ranges;
if there is an intervening load balancer, configure that hop separately.
