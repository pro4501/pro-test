"""HTTP layer - everything that talks to the target over the network.

request.py   Request model: URL, method, query/body/file parameters. Requests are hashable so the
             crawler can de-duplicate them and the persister can store them as JSON.
response.py  Response model with case-insensitive headers and helpers (is_redirect, is_server_error...).
client.py    Thread-safe client built on urllib. Never follows redirects automatically (the scanner
             must see 3xx answers), applies the rate limit and backs off on HTTP 429/503.
scope.py     Scope rules deciding which URLs may be crawled/attacked (url, page, folder, domain...).
             Staying in scope is both a correctness and an ethical/legal requirement.
auth.py      Authentication helpers: cookie files, HTTP auth check, login-form autodetection.

Named "net" rather than "http" so it does not shadow Python's own ``http`` package.
"""
