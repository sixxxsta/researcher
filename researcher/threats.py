from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass


SQL_INJECTION_PARTS = (
    "union select",
    "union+select",
    "union%20select",
    "or 1=1",
    "or+1%3d1",
    "' or '1'='1",
    "information_schema",
    "sleep(",
    "benchmark(",
    "extractvalue(",
    "updatexml(",
    "load_file(",
    "into outfile",
    "into+dumpfile",
)

XSS_PARTS = (
    "<script",
    "%3cscript",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
    "document.cookie",
    "<iframe",
    "%3ciframe",
)

COMMAND_INJECTION_PARTS = (
    ";cat ",
    "|cat ",
    "`cat ",
    "$(cat",
    ";wget ",
    "|wget ",
    ";curl ",
    "|curl ",
    ";bash ",
    "|bash ",
    ";sh ",
    "|sh ",
    "&&cat ",
    "||cat ",
    "%0acat",
    "%0dwget",
)

PATH_TRAVERSAL_PARTS = (
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "/etc/passwd",
    "/etc/shadow",
    "c:\\windows\\",
    "c:/windows/",
    "boot.ini",
)

LFI_RFI_PARTS = (
    "php://",
    "file://",
    "data://",
    "expect://",
    "include=",
    "require=",
    "page=",
    "template=",
    "load=",
)

SSTI_PARTS = (
    "{{7*7}}",
    "${7*7}",
    "<%= ",
    "#{7*7}",
    "{{config",
    "__class__",
    "__mro__",
)

GENERIC_PROBE_PARTS = (
    "/.env",
    "/.git",
    "wp-login.php",
    "xmlrpc.php",
    "phpmyadmin",
    "adminer",
    "shell",
    "webshell",
    "cmd=",
    "exec=",
    "eval(",
    "base64",
    "passwd",
)

DDOS_TOOL_RE = re.compile(
    r"\b("
    r"hping3?|slowloris|slowhttptest|xerosploit|goldeneye|torshammer|ufonet|"
    r"loic|hoic|ddos|stresser|botnet|synflood|udp flood|icmp flood|"
    r"memcached amplification|ntp amplification|dns amplification"
    r")\b",
    re.IGNORECASE,
)

SCAN_TOOL_RE = re.compile(
    r"\b("
    r"nmap|masscan|zmap|unicornscan|rustscan|naabu|nuclei|nikto|sqlmap|gobuster|dirb|dirbuster|ffuf|"
    r"wpscan|hydra|medusa|ncrack|enum4linux|smbclient|rpcclient|crackmapexec|"
    r"impacket|responder|bloodhound|mimikatz|linpeas|winpeas|pspy"
    r")\b",
    re.IGNORECASE,
)

LATERAL_MOVEMENT_RE = re.compile(
    r"\b("
    r"ssh\s+-o\s+StrictHostKeyChecking=no|sshpass|proxychains|tor\s|torsocks|"
    r"chisel|ligolo|ngrok|frp\s|metasploit|msfconsole|meterpreter|"
    r"reverse shell|bind shell|/dev/tcp/|socat\s|nc\s+-e|ncat\s|"
    r"powershell\s+-enc|powershell\s+-e\s|"
    r"iex\s*\(|invoke-expression|downloadstring|downloadfile"
    r")\b",
    re.IGNORECASE,
)

EXTORTION_RE = re.compile(
    r"\b("
    r"bitcoin|monero|xmr|bc1[a-z0-9]{10,}|1[a-km-zA-HJ-NP-Z1-9]{25,34}|"
    r"ransom|decrypt|restore[_ -]?your[_ -]?files|how[_ -]?to[_ -]?decrypt|"
    r"lockbit|blackcat|conti|revil|ryuk|encrypted|\.locked|pay[_ -]?btc"
    r")\b",
    re.IGNORECASE,
)

CRYPTO_WALLET_RE = re.compile(
    r"\b(?:bc1[a-z0-9]{20,}|1[a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b"
)

RANSOM_NOTE_NAME_PARTS = (
    "readme_decrypt",
    "recover_files",
    "how_to_decrypt",
    "decrypt_instructions",
    "restore_files",
    "your_files",
    "ransom",
    "encrypted",
    "lockbit",
    "help_decrypt",
)


def classify_url_threat(url: str) -> str | None:
    lowered = url.lower()
    if any(part in lowered for part in SQL_INJECTION_PARTS):
        return "sql_injection"
    if any(part in lowered for part in XSS_PARTS):
        return "xss_attempt"
    if any(part in lowered for part in COMMAND_INJECTION_PARTS):
        return "command_injection"
    if any(part in lowered for part in PATH_TRAVERSAL_PARTS):
        return "path_traversal"
    if any(part in lowered for part in LFI_RFI_PARTS):
        return "lfi_rfi_attempt"
    if any(part in lowered for part in SSTI_PARTS):
        return "ssti_attempt"
    if any(part in lowered for part in GENERIC_PROBE_PARTS):
        return "suspicious_web_request"
    return None


def classify_command_threat(line: str) -> str | None:
    if DDOS_TOOL_RE.search(line):
        return "ddos_tool_usage"
    if SCAN_TOOL_RE.search(line):
        return "scan_tool_usage"
    if LATERAL_MOVEMENT_RE.search(line):
        return "lateral_movement"
    if EXTORTION_RE.search(line) or CRYPTO_WALLET_RE.search(line):
        return "extortion_indicator"
    return None


def is_ransom_note_name(name: str) -> bool:
    lowered = name.lower()
    return any(part in lowered for part in RANSOM_NOTE_NAME_PARTS)


def threat_kind_label(kind: str) -> str:
    return {
        "sql_injection": "SQL injection",
        "xss_attempt": "XSS attempt",
        "command_injection": "Command injection",
        "path_traversal": "Path traversal",
        "lfi_rfi_attempt": "LFI/RFI attempt",
        "ssti_attempt": "SSTI attempt",
        "suspicious_web_request": "Suspicious web request",
        "ddos_tool_usage": "DDoS/stress tool usage",
        "scan_tool_usage": "Scanner/exploit tool usage",
        "lateral_movement": "Lateral movement / pivot",
        "extortion_indicator": "Extortion/ransom indicator",
    }.get(kind, kind)


INJECTION_KINDS = {
    "sql_injection",
    "xss_attempt",
    "command_injection",
    "path_traversal",
    "lfi_rfi_attempt",
    "ssti_attempt",
    "suspicious_web_request",
}

OUTBOUND_ATTACK_KINDS = {
    "ddos_tool_usage",
    "scan_tool_usage",
    "lateral_movement",
}

EXTORTION_KINDS = {
    "extortion_indicator",
}

IP_IN_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9_.:-])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4})"
    r"(?![A-Za-z0-9_.:-])"
)


@dataclass(frozen=True)
class OutboundIpHit:
    ip: str
    role: str
    threat_kind: str
    source: str
    line_number: int = 0
    evidence: str = ""


def normalize_ip(value: str, include_private: bool = True) -> str | None:
    cleaned = value.strip("[],:;\"'")
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return None
    if not include_private and not ip.is_global:
        return None
    return str(ip)


def extract_ips_from_text(text: str, include_private: bool = True) -> list[str]:
    seen: set[str] = set()
    ips: list[str] = []
    for match in IP_IN_TEXT_RE.finditer(text):
        ip = normalize_ip(match.group("ip"), include_private)
        if ip and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def collect_outbound_ip_hits(events, findings, include_private: bool = True) -> list[OutboundIpHit]:
    hits: list[OutboundIpHit] = []

    for event in events:
        if event.kind not in OUTBOUND_ATTACK_KINDS:
            continue
        evidence = event.raw or ""
        evidence_ips = extract_ips_from_text(evidence, include_private)
        if event.ip:
            hits.append(
                OutboundIpHit(
                    ip=event.ip,
                    role="actor",
                    threat_kind=event.kind,
                    source=event.source,
                    line_number=event.line_number,
                    evidence=evidence[:300],
                )
            )
        for ip in evidence_ips:
            if ip == event.ip and len(evidence_ips) == 1:
                continue
            hits.append(
                OutboundIpHit(
                    ip=ip,
                    role="target",
                    threat_kind=event.kind,
                    source=event.source,
                    line_number=event.line_number,
                    evidence=evidence[:300],
                )
            )

    for finding in findings:
        if finding.kind not in OUTBOUND_ATTACK_KINDS:
            continue
        evidence = finding.value or finding.detail or ""
        for ip in extract_ips_from_text(evidence, include_private):
            hits.append(
                OutboundIpHit(
                    ip=ip,
                    role="target",
                    threat_kind=finding.kind,
                    source=finding.path,
                    line_number=finding.line_number or 0,
                    evidence=evidence[:300],
                )
            )

    return hits


def summarize_outbound_ip_hits(hits: list[OutboundIpHit]) -> dict[str, dict[str, object]]:
    grouped: dict[str, dict[str, object]] = defaultdict(
        lambda: {
            "roles": Counter(),
            "kinds": Counter(),
            "sources": Counter(),
            "hits": 0,
        }
    )
    for hit in hits:
        bucket = grouped[hit.ip]
        bucket["hits"] = int(bucket["hits"]) + 1
        roles = bucket["roles"]
        kinds = bucket["kinds"]
        sources = bucket["sources"]
        assert isinstance(roles, Counter)
        assert isinstance(kinds, Counter)
        assert isinstance(sources, Counter)
        roles[hit.role] += 1
        kinds[hit.threat_kind] += 1
        sources[hit.source] += 1
    return dict(grouped)


def summarize_threat_events(events) -> Counter[str]:
    return Counter(event.kind for event in events if event.kind in INJECTION_KINDS | OUTBOUND_ATTACK_KINDS | EXTORTION_KINDS)
