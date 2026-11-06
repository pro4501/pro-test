"""Authentication helpers: cookie files, HTTP auth check and login forms.

Most interesting pages of a web application are behind a login, so an unauthenticated scan only
sees the public surface. Ways to give the scanner a session:

    load_cookie_file()     import cookies exported from a browser (JSON)
    check_http_auth()      verify HTTP Basic/Digest credentials before crawling
    try_form_login()       find the login form, fill username/password, submit it, and detect
                           success (login form gone or a logout link present). Logout links are
                           returned so the crawler excludes them and does not end its own session.
    login_with_raw_data()  POST a raw body you captured from your browser
"""
import http.cookiejar
import json
import re
import time
from typing import List, Optional, Tuple

from protest.core import log
from protest.parsing.page import Html
from protest.net.client import HttpClient, InvalidURL, RequestError
from protest.net.request import Request, parse_qsl

LOGOUT_PATTERN = re.compile(r"log\s*-?\s*out|sign\s*-?\s*out|logoff|deconnexion|disconnect|exit", re.I)


def _make_cookie(name: str, value: str, domain: str, path: str = "/", secure: bool = False,
                 expires: Optional[int] = None) -> http.cookiejar.Cookie:
    return http.cookiejar.Cookie(
        version=0, name=name, value=value, port=None, port_specified=False,
        domain=domain, domain_specified=domain.startswith("."), domain_initial_dot=domain.startswith("."),
        path=path or "/", path_specified=True, secure=secure, expires=expires, discard=expires is None,
        comment=None, comment_url=None, rest={}, rfc2109=False,
    )


def load_cookie_file(filename: str, jar: http.cookiejar.CookieJar, default_domain: str) -> int:
    """Load cookies from JSON. Supported layouts:
    - Wapiti's: {"domain": {"/path": {"name": {"value": ..., "secure": ..., "expires": ...}}}}
    - browser export: [{"name": ..., "value": ..., "domain": ..., "path": ...}, ...]
    - simple: {"name": "value", ...}
    """
    with open(filename, encoding="utf-8") as handle:
        data = json.load(handle)
    count = 0
    if isinstance(data, list):
        for item in data:
            jar.set_cookie(_make_cookie(item["name"], str(item.get("value", "")), item.get("domain", default_domain),
                                        item.get("path", "/"), bool(item.get("secure")),
                                        int(item["expirationDate"]) if item.get("expirationDate") else None))
            count += 1
    elif isinstance(data, dict) and all(isinstance(v, dict) for v in data.values()):
        for domain, paths in data.items():
            for path, cookies in paths.items():
                for name, attrs in cookies.items():
                    if isinstance(attrs, dict):
                        jar.set_cookie(_make_cookie(name, str(attrs.get("value", "")), domain, path,
                                                    bool(attrs.get("secure")), attrs.get("expires")))
                    else:
                        jar.set_cookie(_make_cookie(name, str(attrs), domain, path))
                    count += 1
    elif isinstance(data, dict):
        for name, value in data.items():
            jar.set_cookie(_make_cookie(name, str(value), default_domain))
            count += 1
    return count


def check_http_auth(client: HttpClient, url: str) -> bool:
    try:
        response = client.send(Request(url))
    except (RequestError, InvalidURL):
        return False
    return response.status not in (401, 403, 407)


def _logout_urls(content: str, url: str) -> List[str]:
    page = Html(content, url)
    urls = []
    for node in page.root.find_all(("a",), "href"):
        text = node.get_text() + " " + node.attrs.get("href", "")
        if LOGOUT_PATTERN.search(text):
            absolute = page._absolute(node.attrs["href"])  # pylint: disable=protected-access
            if absolute:
                urls.append(absolute)
    return urls


def try_form_login(client: HttpClient, form_url: str, username: str, password: str) -> Tuple[bool, dict, List[str]]:
    """Fill and submit the login form found at form_url. Returns (logged_in, form_info, logout_urls)."""
    try:
        page = client.send(Request(form_url), follow_redirects=True)
    except (RequestError, InvalidURL) as error:
        log.error(f"[!] Could not fetch the login page: {error}")
        return False, {}, []

    html = Html(page.content, page.url)
    login_form = next((form for form in html.iter_forms() if form.has_password_field()), None)
    if login_form is None:
        log.error(f"[!] No form with a password field found on {form_url}")
        return False, {}, []

    user_field = next((f.name for f in login_form.fields if f.tag_type in ("text", "email")
                       and re.search(r"user|login|mail|name|account|ident", f.name, re.I)), None)
    if user_field is None:
        user_field = next((f.name for f in login_form.fields if f.tag_type in ("text", "email")), None)
    pass_field = next(f.name for f in login_form.fields if f.tag_type == "password")

    request = login_form.to_requests()[0]
    params = request.post_params if request.method == "POST" else request.get_params
    filled = [[k, username if k == user_field else password if k == pass_field else v] for k, v in params]
    if request.method == "POST":
        login_request = Request(request.path, method="POST", get_params=request.get_params, post_params=filled,
                                enctype=request.enctype, referer=page.url)
    else:
        login_request = Request(request.path, method="GET", get_params=filled, referer=page.url)

    try:
        result = client.send(login_request, follow_redirects=True)
    except (RequestError, InvalidURL) as error:
        log.error(f"[!] Login request failed: {error}")
        return False, {}, []

    result_html = Html(result.content, result.url)
    still_login_form = any(form.has_password_field() for form in result_html.iter_forms())
    logout_urls = _logout_urls(result.content, result.url)
    logged_in = bool(logout_urls) or (not still_login_form and result.status < 400)
    form_info = {"login_field": user_field, "password_field": pass_field, "url": login_request.path}
    if logged_in:
        log.log_green(f"[+] Login success on {form_url}")
    else:
        log.warning(f"[!] Login probably failed on {form_url}")
    time.sleep(0.1)
    return logged_in, form_info, logout_urls


def login_with_raw_data(client: HttpClient, url: str, data: str, enctype: str) -> bool:
    if "json" in enctype:
        request = Request(url, method="POST", post_params=data, enctype=enctype)
    else:
        request = Request(url, method="POST", post_params=parse_qsl(data), enctype=enctype)
    try:
        response = client.send(request, follow_redirects=True)
    except (RequestError, InvalidURL) as error:
        log.error(f"[!] Login request failed: {error}")
        return False
    return response.status < 400
