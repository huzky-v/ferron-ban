# Plain-text HTTP error responses

The custom Ferron binary in this repository includes an optional module that
renders Ferron's HTTP error-pipeline responses as one-line plain text instead
of the default HTML page. Enable it in the global configuration block to use
it for all HTTP hosts:

```text
{
    text_errors true
}
```

It can also be enabled or disabled for an individual HTTP host:

```text
example.com:443 {
    text_errors true
}

api.example.com:443 {
    text_errors false
}
```

The directive accepts a boolean. `text_errors` without an argument is also
treated as enabled. When enabled, the response body contains the status code,
a space, the canonical reason phrase, and a trailing newline; for example,
`404 Not Found\n`. Status codes without a canonical reason phrase use
`Unknown`. The response retains the error status, sets
`Content-Type: text/plain; charset=utf-8`, and preserves additional headers
attached to the error context.

This applies to errors handled through Ferron's HTTP error pipeline, when no
response has already been rendered. It is not a general rewrite of response
bodies returned by a proxied upstream. The text response takes precedence over
the file-based `error_page` stage for applicable errors.

The current unit tests check plain-text bodies for 400, 403, 404, 429, 500,
and 503, along with the disabled setting, an already-rendered response,
additional headers, and unknown reason phrases. These are stage-level tests;
there is not currently a live-server integration test for enabling the
directive through configuration.
