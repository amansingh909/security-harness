"""Endpoint and parameter discovery for active testing.

Active testing is only useful if it injects into the app's *real* inputs, not a
guessed parameter on the host root. This module fetches a page and pulls out the
injection points a reflected/error-based issue would actually surface through:

* links that carry query parameters (``/search?q=…``)
* GET form fields (``<form method=get action=/find><input name=term>``)

POST forms are skipped on purpose — active mode is GET-only so it never changes
state, even on your own boxes. Every discovered URL is scope-checked by the
caller before it is touched.
"""
from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

MAX_INJECTION_POINTS = 40


@dataclass(frozen=True)
class InjectionPoint:
    url: str                                    # scheme://host/path, no query
    param: str                                  # the parameter to inject into
    base_params: tuple[tuple[str, str], ...]    # sibling params to preserve
    source: str                                 # "link" | "form"

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def path(self) -> str:
        return urlparse(self.url).path or "/"


class _Extractor(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._page_url = page_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = {k: (v or "") for k, v in attrs}
        if tag == "a" and d.get("href"):
            self.links.append(urljoin(self._page_url, d["href"]))
        elif tag == "form":
            action = urljoin(self._page_url, d.get("action") or self._page_url)
            self._form = {"action": action,
                          "method": (d.get("method") or "get").lower(),
                          "params": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = d.get("name")
            if name:
                self._form["params"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _strip_query(url: str) -> str:
    u = urlparse(url)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, "", ""))


def extract_injection_points(
    page_url: str, html: str, max_points: int = MAX_INJECTION_POINTS
) -> list[InjectionPoint]:
    """Return de-duplicated (endpoint, param) injection points from a page."""
    ex = _Extractor(page_url)
    try:
        ex.feed(html)
        ex.close()
    except Exception:  # noqa: BLE001 - malformed HTML must not crash discovery
        pass
    if ex._form is not None:            # a form left unclosed by the page
        ex.forms.append(ex._form)

    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()

    def add(base: str, param: str, siblings: list[tuple[str, str]], source: str) -> None:
        key = (base, param)
        if key in seen or not param:
            return
        seen.add(key)
        points.append(InjectionPoint(base, param, tuple(siblings), source))

    # Links that already carry query parameters.
    for link in ex.links:
        u = urlparse(link)
        if not u.scheme.startswith("http"):
            continue
        qs = parse_qsl(u.query, keep_blank_values=True)
        if not qs:
            continue
        base = _strip_query(link)
        for i, (name, _) in enumerate(qs):
            siblings = [kv for j, kv in enumerate(qs) if j != i]
            add(base, name, siblings, "link")
            if len(points) >= max_points:
                return points

    # GET forms (POST is skipped to stay state-safe).
    for form in ex.forms:
        if form["method"] != "get":
            continue
        base = _strip_query(form["action"])
        if not urlparse(base).scheme.startswith("http"):
            continue
        existing = parse_qsl(urlparse(form["action"]).query, keep_blank_values=True)
        for name in form["params"]:
            add(base, name, existing, "form")
            if len(points) >= max_points:
                return points

    return points


def inject(point: InjectionPoint, value: str) -> str:
    """Build a URL that puts ``value`` in ``point.param``, preserving siblings."""
    params = list(point.base_params) + [(point.param, value)]
    return f"{point.url}?{urlencode(params)}"
