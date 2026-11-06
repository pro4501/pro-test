# Viva study guide

Use this with the source, not instead of it. The questions are about this edition. Answers name the function that does the work.

This file does not claim that the project meets a novelty bar or that a grade will follow. No brief or rubric was provided. If you were helped by an AI assistant, say so in the form your university requires. Do not hide that. The copyright line on the source follows the rest of the Pro-Test repository (Pratham Brahmbhatt). It is not a statement that every line was typed with no assistance.

Upstream-derived material in the parent repository (sqlmap error expressions, shared Wapiti lines) is listed in the parent `NOTICE`. This edition does not include those expressions. The ideas "crawl HTML" and "read security headers" are ordinary. The modules here were written as a small teaching program and were drafted with AI assistance.

## Questions

### 1. What does "same origin" mean here?

`scope.origin` returns scheme, lowercased hostname, and port. Missing ports become 80 or 443. `same_origin` is true only when those three match. `http://127.0.0.1/a` and `http://127.0.0.1:9/b` are different. `file:///tmp/x` is rejected by `require_web_url` and `same_origin` returns false.

### 2. Why is the redirect not followed inside `fetch`?

`fetch` installs `_NoRedirect`. A 302 comes back as a `FetchedPage` with a `location` string. `crawl` then calls `_redirect_target`. That queues the target only if `same_origin` accepts it. A `file:` location becomes the notice "Redirect not followed" and is not passed to `fetch`. The test `test_redirects_off_origin_are_not_requested` counts the requests the fixture saw: one.

### 3. When is a password field reported?

`cleartext_password` counts `<input type="password">` with `parse.read_page`. It returns a vulnerability only when the URL's scheme is `http`. The same HTML with an `https` URL returns an empty list. That is a true positive and a false positive check of the rule, not a claim that the form was submitted.

### 4. Why do some findings stop the scan and others do not?

`Finding.kind` is `vulnerability` or `notice`. Cookie flags and the cleartext field are vulnerabilities. Missing framing and `nosniff` headers are notices. `Pause.observe` returns immediately unless the kind is `vulnerability`. The tests construct a protected response and expect no findings, and a bare HTML response and expect only notices.

### 5. What does Enter do at the prompt?

`Pause._prompt` treats `""` and `"2"` as stop, and end-of-file as stop. `"1"` continues. `resolve_policy` uses `ask` when stdin is a terminal and no flag was passed. Otherwise the policy is `stop`, and the command prints that `--on-finding continue` keeps scanning. The default is not a silent continue.

### 6. How can a stop avoid the next page?

`crawl` calls `pause.observe` before it reads links. If that sets `stopped`, the function `continue`s the loop and does not call `resolve_link`. The next loop sees `stopped` and breaks before `before_request`. `test_stop_does_not_fetch_the_next_page_and_keeps_the_report` records the paths the server received. The list is `["/"]`, and the report contains the cleartext finding and `Stopped early: yes`.

### 7. Does "passive" mean no network traffic?

No. `fetch` sends a GET. Passive here means the scanner does not send a second request with a changed parameter. Say that plainly. The report's last sentence is the same limit: the lines describe responses.

### 8. What does this edition leave out of the full tool, on purpose?

No login, no credential vault, no active injection, no database extraction, no thread pool, no domain-wide scope, and one report format. The full tool still has those. Its default when `-m` is omitted is the passive set; its active modules are opt-in. This edition is not a wrapper that calls them.

### 9. What should you be able to change in the room?

Add a notice for one header you can point at in `header_notices`, or explain why `cookie_flags` does not copy the cookie value into the evidence string. You should also be able to start `examples/server.py` and show one stop and one continue.

### 10. What will you not claim?

You will not claim a finding is an exploit. You will not claim the 7 unit tests are a security audit. You will not claim the full scanner's sqlmap patterns live in this directory. You will not claim a mark.

## Short answers you can say out loud

- "Origin is scheme, host, and port. I check it in `same_origin` before `fetch`."
- "Stop is a flag. `before_request` raises before the next GET. The report is already built from the pages list."
- "HttpOnly missing is a vulnerability I pause on. A missing `X-Frame-Options` is a notice I only record."
- "The full program is `pro-test`. This one is `pro-test-msc`. I installed them with `pipx` from two directories."
