# Choose a Compose definitions source

- **Legacy database + templates:** Follow the commands in
  [`docker-compose.yml`](docker-compose.yml). Run the definitions initializer,
  provision SQLite rows and matching YAML, then run `docker compose up -d`.
  This mounts the DB volume and the template directory separately.
- **Single ZIP bundle:** Prepare `abuse-bundle.zip` in this directory, then run
  `docker compose -f docker-compose.bundle.yml up -d`. This standalone Compose
  file uses [`ferron-bundle.conf`](ferron-bundle.conf), mounts only the bundle
  (read-only) for definitions and responses, and has **no initializer job or
  dependency**. Do not combine it with the legacy Compose file. Build the
  runtime image as described in `docker-compose.yml` or set `FERRON_IMAGE`.

The bundle must contain a checkpointed, self-contained SQLite database named
`definitions.sqlite` at the ZIP root, plus
`honeypot-responses/<definition-name>.yaml` for each enabled `id_leak` rule
when honeypot mode is enabled. Do not rely on an external SQLite `-wal` or
`-shm` file. Provision definitions and matching YAML before packaging; neither
the image nor this Compose file generates the bundle. Restart Ferron to load
an updated ZIP. Whenever the bundle is loaded, its archive structure, entry
safety, entry types, and size limits are validated. With honeypot mode disabled
and ban mode enabled, the database is validated but YAML catalog/content
validation is skipped; response YAML files are not required. When both modes
are disabled, the bundle is not fetched or validated. See
[`honeypot-responses.md`](../../docs/honeypot-responses.md) for the layout,
validation rules, and the local-path/HTTPS `definitions_bundle` alternatives.
