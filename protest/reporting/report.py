# Copyright (C) Pratham Brahmbhatt
# SPDX-License-Identifier: GPL-2.0-or-later
# Licensed under the GNU GPL, version 2 or any later version. See LICENSE and NOTICE.
"""Report generators: html, json, txt, csv, md and xml.

ReportGenerator collects StoredFinding objects (from the SQLite session) into three sections:
vulnerabilities, anomalies (500 errors, timeouts) and additional information (fingerprints...).
Each entry keeps the same fields in every format: severity, confidence, URL, parameter, payload,
evidence, the raw HTTP request and a curl command to reproduce it. Each subclass only implements
generate(), i.e. how to render those entries, which is a simple example of the Template Method
design pattern.
"""
import csv
import html
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Optional

from protest.core.definitions import (
    ADDITIONAL, ALL_FINDINGS, ANOMALY, CONFIDENCE_ORDER, LEVEL_NAMES, VULNERABILITY, Finding,
)
from protest.core.persister import StoredFinding

SECTIONS = ((VULNERABILITY, "vulnerabilities", "Vulnerabilities"),
            (ANOMALY, "anomalies", "Anomalies"),
            (ADDITIONAL, "additionals", "Additional information"))


class ReportGenerator:
    extension = "txt"

    def __init__(self):
        self.infos: dict = {}
        self.findings: Dict[str, Dict[str, List[dict]]] = {key: {} for _, key, _ in SECTIONS}
        self.classifications: Dict[str, Finding] = {f.name: f for f in ALL_FINDINGS}
        self.crawled: List[dict] = []
        self.detailed_level = 0

    # pylint: disable=too-many-arguments
    def set_report_info(self, target: str, scope: str, version: str, auth: Optional[dict], crawled_count: int,
                        detailed_level: int = 0, crawled: Optional[List[dict]] = None):
        self.detailed_level = detailed_level
        self.crawled = crawled or []
        self.infos = {
            "target": target,
            "date": datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000"),
            "version": version,
            "scope": scope,
            "auth": auth,
            "crawled_pages_nbr": crawled_count,
            "detailed_report_level": detailed_level,
        }

    def add_finding(self, item: StoredFinding):
        section = {VULNERABILITY: "vulnerabilities", ANOMALY: "anomalies", ADDITIONAL: "additionals"}[item.type]
        request = item.request
        entry = {
            "method": request.method if request else "",
            "path": request.file_path if request else "",
            "url": request.url if request else "",
            "info": item.info,
            "level": item.level,
            "severity": LEVEL_NAMES.get(item.level, str(item.level)),
            "parameter": item.parameter,
            "payload": item.payload,
            "evidence": item.evidence,
            "confidence": item.confidence or "",
            "referer": request.referer if request else "",
            "module": item.module,
            "http_request": request.http_repr(left_margin="") if request else "",
            "curl_command": request.curl_repr() if request else "",
            "wstg": item.wstg,
        }
        if self.detailed_level >= 2 and item.response is not None:
            entry["detail"] = {"response": {
                "status_code": item.response.status,
                "headers": item.response.headers.items(),
                "body": item.response.content[:10000],
            }}
        self.findings[section].setdefault(item.category, []).append(entry)

    def severity_counts(self) -> Dict[str, int]:
        result = {name: 0 for name in LEVEL_NAMES.values()}
        for section in self.findings.values():
            for items in section.values():
                for item in items:
                    result[item["severity"]] += 1
        return result

    def categories(self, section_type: str) -> List[Finding]:
        return [f for f in ALL_FINDINGS if f.type == section_type]

    def generate(self, output: str) -> str:
        raise NotImplementedError


class JsonReportGenerator(ReportGenerator):
    extension = "json"

    def generate(self, output: str) -> str:
        data = {
            "classifications": {
                f.name: {"desc": f.description, "sol": f.solution, "ref": {r["title"]: r["url"] for r in f.references},
                         "wstg": f.wstg}
                for f in ALL_FINDINGS
            },
            "vulnerabilities": {f.name: self.findings["vulnerabilities"].get(f.name, [])
                                for f in self.categories(VULNERABILITY)},
            "anomalies": {f.name: self.findings["anomalies"].get(f.name, []) for f in self.categories(ANOMALY)},
            "additionals": {f.name: self.findings["additionals"].get(f.name, []) for f in self.categories(ADDITIONAL)},
            "infos": self.infos,
        }
        if self.detailed_level:
            data["infos"]["crawled_pages"] = self.crawled
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
        return output


class TxtReportGenerator(ReportGenerator):
    extension = "txt"

    def generate(self, output: str) -> str:
        lines = []
        bar = "*" * 80
        lines += [bar, f"{self.infos['version']} - web application vulnerability report".center(80), bar, ""]
        lines += [f"Target: {self.infos['target']}", f"Date of the scan: {self.infos['date']}",
                  f"Scope of the scan: {self.infos['scope']}",
                  f"Crawled pages: {self.infos['crawled_pages_nbr']}", ""]
        if self.infos.get("auth"):
            auth = self.infos["auth"]
            lines.append(f"Authentication: {auth.get('url')} - {'logged in' if auth.get('logged_in') else 'FAILED'}")
            lines.append("")
        for section_type, key, title in SECTIONS:
            lines += ["-" * 80, f"Summary of {title.lower()}:", "-" * 80]
            for finding in self.categories(section_type):
                count = len(self.findings[key].get(finding.name, []))
                lines.append(f"{finding.name:.<60}{count:.>20}")
            lines.append("")
        for section_type, key, title in SECTIONS:
            for finding in self.categories(section_type):
                items = self.findings[key].get(finding.name, [])
                if not items:
                    continue
                lines += [bar, f"{finding.name} ({title})", bar, f"Description: {finding.description}",
                          f"Solution: {finding.solution}", f"WSTG: {', '.join(finding.wstg)}", ""]
                for item in items:
                    lines += [f"[{item['severity']} | {item['confidence']}] {item['info']}",
                              f"Module: {item['module']}"]
                    if item["parameter"]:
                        lines.append(f"Vulnerable parameter: {item['parameter']}")
                    if item["payload"]:
                        lines.append(f"Payload: {item['payload']}")
                    if item["evidence"]:
                        lines += ["Evidence:", "    " + item["evidence"].replace("\n", "\n    ")]
                    if item["http_request"]:
                        lines += ["", item["http_request"], "", f"cURL: {item['curl_command']}"]
                    lines += ["", "-" * 40, ""]
        with open(output, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
        return output


class CsvReportGenerator(ReportGenerator):
    extension = "csv"

    def generate(self, output: str) -> str:
        with open(output, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["type", "category", "severity", "confidence", "method", "url", "parameter", "payload",
                             "evidence", "info", "module", "wstg", "curl"])
            for section_type, key, _ in SECTIONS:
                for category, items in self.findings[key].items():
                    for item in items:
                        writer.writerow([section_type, category, item["severity"], item["confidence"],
                                         item["method"], item["url"],
                                         item["parameter"], item["payload"], item["evidence"], item["info"],
                                         item["module"], " ".join(item["wstg"]), item["curl_command"]])
        return output


class MarkdownReportGenerator(ReportGenerator):
    extension = "md"

    def generate(self, output: str) -> str:
        out = [f"# {self.infos['version']} report", "",
               f"* **Target:** {self.infos['target']}", f"* **Date:** {self.infos['date']}",
               f"* **Scope:** {self.infos['scope']}", f"* **Crawled pages:** {self.infos['crawled_pages_nbr']}", ""]
        for section_type, key, title in SECTIONS:
            out += [f"## Summary of {title.lower()}", "", "| Category | Count |", "|---|---|"]
            for finding in self.categories(section_type):
                out.append(f"| {finding.name} | {len(self.findings[key].get(finding.name, []))} |")
            out.append("")
        for section_type, key, title in SECTIONS:
            for finding in self.categories(section_type):
                items = self.findings[key].get(finding.name, [])
                if not items:
                    continue
                out += [f"## {finding.name}", "", f"**Description:** {finding.description}", "",
                        f"**Solution:** {finding.solution}", "", f"**WSTG:** {', '.join(finding.wstg)}", ""]
                for item in items:
                    out += [f"### [{item['severity']}] {item['info']}", "", f"* Module: `{item['module']}`",
                            f"* Confidence: **{item['confidence']}**"]
                    if item["parameter"]:
                        out.append(f"* Parameter: `{item['parameter']}`")
                    if item["payload"]:
                        out += ["", "**Payload**", "", "```text", item["payload"], "```"]
                    if item["evidence"]:
                        out += ["", "**Evidence**", "", "```text", item["evidence"], "```"]
                    if item["http_request"]:
                        out += ["", "```http", item["http_request"], "```", "", "```bash", item["curl_command"],
                                "```"]
                    out.append("")
        with open(output, "w", encoding="utf-8") as handle:
            handle.write("\n".join(out))
        return output


class XmlReportGenerator(ReportGenerator):
    extension = "xml"

    def generate(self, output: str) -> str:
        root = ET.Element("report", type="security")
        info = ET.SubElement(root, "report_infos")
        for key in ("target", "date", "version", "scope", "crawled_pages_nbr"):
            ET.SubElement(info, "info", name=key).text = str(self.infos.get(key, ""))
        for section_type, key, _ in SECTIONS:
            section = ET.SubElement(root, key)
            for finding in self.categories(section_type):
                node = ET.SubElement(section, section_type, name=finding.name)
                ET.SubElement(node, "description").text = finding.description
                ET.SubElement(node, "solution").text = finding.solution
                refs = ET.SubElement(node, "references")
                for ref in finding.references:
                    ref_node = ET.SubElement(refs, "reference")
                    ET.SubElement(ref_node, "title").text = ref["title"]
                    ET.SubElement(ref_node, "url").text = ref["url"]
                entries = ET.SubElement(node, "entries")
                for item in self.findings[key].get(finding.name, []):
                    entry = ET.SubElement(entries, "entry")
                    for field in ("method", "path", "url", "level", "severity", "confidence", "parameter", "payload",
                                  "evidence",
                                  "referer", "module", "info", "http_request", "curl_command"):
                        ET.SubElement(entry, field).text = str(item[field])
                    wstg = ET.SubElement(entry, "wstg")
                    for code in item["wstg"]:
                        ET.SubElement(wstg, "code").text = code
        tree = ET.ElementTree(root)
        ET.indent(tree)
        tree.write(output, encoding="utf-8", xml_declaration=True)
        return output


HTML_STYLE = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5b6577;--border:#dde1e8;--accent:#2d5be3;
--critical:#8e1b1b;--high:#d63b3b;--medium:#e48a1a;--low:#c9b20e;--info:#3b82c4;--code:#f1f3f6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--text:#e6e9ef;--muted:#9aa4b5;
--border:#2c3340;--code:#232a35}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--text)}header{background:var(--accent);color:#fff;padding:24px 16px}
header h1{margin:0 0 4px;font-size:22px}header p{margin:0;opacity:.9;word-break:break-all}
main{max-width:1100px;margin:0 auto;padding:16px}.card{background:var(--card);border:1px solid var(--border);
border-radius:8px;padding:16px;margin-bottom:16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,
minmax(120px,1fr));gap:10px}.tile{border-radius:6px;padding:10px;color:#fff;text-align:center}
.tile b{display:block;font-size:24px}table{width:100%;border-collapse:collapse}td,th{text-align:left;
padding:6px 8px;border-bottom:1px solid var(--border)}td.n{text-align:right;font-variant-numeric:tabular-nums}
details{border:1px solid var(--border);border-radius:6px;margin:8px 0;background:var(--card)}
summary{cursor:pointer;padding:10px 12px;font-weight:600}details .body{padding:0 12px 12px}
pre{background:var(--code);padding:10px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;
word-break:break-all;font-size:13px}.badge{display:inline-block;color:#fff;border-radius:4px;padding:1px 7px;
font-size:12px;margin-right:6px}.muted{color:var(--muted)}a{color:var(--accent)}
.Critical{background:var(--critical)}.High{background:var(--high)}.Medium{background:var(--medium)}
.Low{background:var(--low)}.Info{background:var(--info)}
h4{margin:12px 0 4px;font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
pre.evidence{border-left:4px solid var(--high)}pre.payload{border-left:4px solid var(--accent)}
.conf{display:inline-block;border:1px solid currentColor;border-radius:4px;padding:0 6px;font-size:12px;
margin-right:6px;font-weight:600}.conf.Confirmed{color:#1f9d55}.conf.Probable{color:#b7791f}
.conf.Possible{color:var(--muted)}
"""


class HtmlReportGenerator(ReportGenerator):
    extension = "html"

    def generate(self, output: str) -> str:
        esc = html.escape
        severities = self.severity_counts()
        parts = [
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1'>",
            f"<title>Pro-Test report</title><style>{HTML_STYLE}</style></head><body>",
            f"<header><h1>{esc(self.infos['version'])} report</h1><p>{esc(self.infos['target'])}</p></header><main>",
            "<div class='card'><table>",
            f"<tr><th>Date</th><td>{esc(self.infos['date'])}</td></tr>",
            f"<tr><th>Scope</th><td>{esc(self.infos['scope'])}</td></tr>",
            f"<tr><th>Crawled resources</th><td>{self.infos['crawled_pages_nbr']}</td></tr>",
        ]
        if self.infos.get("auth"):
            auth = self.infos["auth"]
            status = "logged in" if auth.get("logged_in") else "login FAILED"
            parts.append(f"<tr><th>Authentication</th><td>{esc(str(auth.get('url')))} ({status})</td></tr>")
        parts.append("</table></div><div class='card grid'>")
        for name, count in severities.items():
            parts.append(f"<div class='tile {name}'><b>{count}</b>{name}</div>")
        parts.append("</div>")
        confidences = {}
        for item in self.findings["vulnerabilities"].values():
            for entry in item:
                confidences[entry["confidence"]] = confidences.get(entry["confidence"], 0) + 1
        if confidences:
            parts.append("<div class='card'><b>Vulnerabilities by confidence:</b> " + " ".join(
                f"<span class='conf {esc(name)}'>{esc(name or '?')}: {count}</span>"
                for name, count in sorted(confidences.items(), key=lambda kv: CONFIDENCE_ORDER.get(kv[0], 3)))
                + "<p class='muted'>Confirmed = reproduced with direct proof &middot; Probable = strong indicator "
                  "&middot; Possible = weak indicator, verify manually</p></div>")

        for section_type, key, title in SECTIONS:
            parts.append(f"<div class='card'><h2>Summary of {esc(title.lower())}</h2><table>")
            for finding in self.categories(section_type):
                count = len(self.findings[key].get(finding.name, []))
                label = f"<a href='#{esc(self._anchor(finding.name))}'>{esc(finding.name)}</a>" if count else \
                    esc(finding.name)
                parts.append(f"<tr><td>{label}</td><td class='n'>{count}</td></tr>")
            parts.append("</table></div>")

        for section_type, key, title in SECTIONS:
            for finding in self.categories(section_type):
                items = self.findings[key].get(finding.name, [])
                if not items:
                    continue
                refs = "".join(f"<li><a href='{esc(r['url'])}' rel='noreferrer'>{esc(r['title'])}</a></li>"
                               for r in finding.references)
                parts.append(
                    f"<div class='card' id='{esc(self._anchor(finding.name))}'><h2>{esc(finding.name)}</h2>"
                    f"<p class='muted'>{esc(title)} &middot; WSTG {esc(', '.join(finding.wstg))}</p>"
                    f"<p><b>Description.</b> {esc(finding.description)}</p>"
                    f"<p><b>Solution.</b> {esc(finding.solution)}</p><ul>{refs}</ul>"
                )
                for item in items:
                    parts.append(
                        f"<details><summary><span class='badge {item['severity']}'>{item['severity']}</span>"
                        f"<span class='conf {esc(item['confidence'])}'>{esc(item['confidence'])}</span>"
                        f"{esc(item['info'])}</summary><div class='body'>"
                        f"<p class='muted'>Module {esc(item['module'])}"
                        + (f" &middot; parameter <code>{esc(item['parameter'])}</code>" if item["parameter"] else "")
                        + "</p>"
                    )
                    if item["payload"]:
                        parts.append(f"<h4>Payload injected</h4><pre class='payload'>{esc(item['payload'])}</pre>")
                    if item["evidence"]:
                        parts.append(f"<h4>Evidence (what the server revealed)</h4>"
                                     f"<pre class='evidence'>{esc(item['evidence'])}</pre>")
                    if item["http_request"]:
                        parts.append(f"<h4>Request to reproduce</h4><pre>{esc(item['http_request'])}</pre>"
                                     f"<pre>{esc(item['curl_command'])}</pre>")
                    if "detail" in item:
                        response = item["detail"]["response"]
                        headers = "\n".join(f"{k}: {v}" for k, v in response["headers"])
                        parts.append(f"<pre>HTTP {response['status_code']}\n{esc(headers)}\n\n"
                                     f"{esc(response['body'][:3000])}</pre>")
                    parts.append("</div></details>")
                parts.append("</div>")
        parts.append("<p class='muted'>Generated by Pro-Test, a pure-Python Wapiti replica. Only scan systems you "
                     "are authorised to test.</p></main></body></html>")
        with open(output, "w", encoding="utf-8") as handle:
            handle.write("".join(parts))
        return output

    @staticmethod
    def _anchor(name: str) -> str:
        return "".join(c if c.isalnum() else "-" for c in name.lower())


GENERATORS = {
    "html": HtmlReportGenerator,
    "json": JsonReportGenerator,
    "txt": TxtReportGenerator,
    "csv": CsvReportGenerator,
    "md": MarkdownReportGenerator,
    "xml": XmlReportGenerator,
}


def resolve_output_path(output: Optional[str], fmt: str, netloc: str, default_dir: str) -> str:
    filename = f"{netloc.replace(':', '_')}_{datetime.now().strftime('%m%d%Y_%H%M%S')}.{fmt}"
    if not output:
        directory = default_dir if fmt == "html" else os.getcwd()
        os.makedirs(directory, exist_ok=True)
        return os.path.join(directory, filename)
    if os.path.isdir(output) or output.endswith(("/", "\\")):
        os.makedirs(output, exist_ok=True)
        return os.path.join(output, filename)
    parent = os.path.dirname(os.path.abspath(output))
    os.makedirs(parent, exist_ok=True)
    return output
