"""Parse only explicitly supported formats; upstream text never controls policy."""
from dataclasses import dataclass
from html.parser import HTMLParser
import ipaddress
import re
from urllib.parse import urlsplit


class Invalid(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str
    flags: tuple[str, ...] = ()

    def render(self, policy):
        return ",".join((self.kind, self.value, policy, *self.flags))


ALIASES = {"HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX",
           "HOST-KEYWORD": "DOMAIN-KEYWORD", "HOST-WILDCARD": "DOMAIN-WILDCARD",
           "IP6-CIDR": "IP-CIDR6"}
TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
         "IP-CIDR", "IP-CIDR6", "IP-ASN", "USER-AGENT", "URL-REGEX"}


def rule(line, policy_column=False):
    parts = [p.strip() for p in line.split(",")]
    kind = ALIASES.get(parts[0].upper(), parts[0].upper())
    if kind not in TYPES or len(parts) < 2 or not parts[1]:
        raise Invalid("Unsupported or empty rule")
    value, tail = parts[1], parts[2:]
    # QX supplies a policy column; SR lists usually supply only optional flags.
    if policy_column:
        if not tail:
            raise Invalid("Missing Quantumult X policy column")
        if not re.fullmatch(r"[\w .+()（）/-]+", tail[0]):
            raise Invalid("Malformed source policy")
        tail = tail[1:]
    if len(tail) > 1 or any(p.lower() != "no-resolve" for p in tail):
        raise Invalid("Unknown rule parameters")
    flags = tuple(p.lower() for p in tail)
    if flags and kind not in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}:
        raise Invalid("no-resolve on non-IP rule")
    if kind.startswith("IP-CIDR"):
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as e:
            raise Invalid("Invalid IP network") from e
        if kind == "IP-CIDR6" and network.version != 6:
            raise Invalid("IPv4 value in IPv6 rule")
        kind = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
        value = str(network)
    elif kind == "IP-ASN":
        if not value.isdecimal() or not 0 < int(value) < 2**32:
            raise Invalid("Invalid ASN")
    elif kind.startswith("DOMAIN"):
        value = value.lower()
        if not re.fullmatch(r"[a-z0-9_*?.-]+", value) or ".." in value:
            raise Invalid("Invalid domain expression")
        if kind in {"DOMAIN", "DOMAIN-SUFFIX"} and any(x in value for x in "*?"):
            raise Invalid("Wildcard in literal domain")
    elif any(ord(c) < 32 for c in value):
        raise Invalid("Control character in expression")
    return Rule(kind, value, flags)


def lines(text):
    return [s for line in text.splitlines()
            if (s := line.strip()) and not s.startswith(("#", ";", "//"))]


def rules(text, policy_column=False):
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", ";", "//")):
            continue
        try:
            result.append(rule(s, policy_column=policy_column))
        except Invalid as e:
            raise Invalid(f"Line {number}: {e}") from e
    if not result:
        raise Invalid("Empty ruleset")
    return result


def sections(text):
    result = {}
    current = None
    for line in lines(text):
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            if current in result:
                raise Invalid("Duplicate configuration section")
            result[current] = []
        elif current is None:
            raise Invalid("Content outside configuration section")
        else:
            result[current].append(line)
    if not {"General", "Rule", "Proxy Group"} <= result.keys():
        raise Invalid("Missing base configuration sections")
    for line in result["Rule"]:
        parts = [p.strip() for p in line.split(",")]
        kind = parts[0]
        if kind == "RULE-SET":
            if len(parts) != 3 or urlsplit(parts[1]).scheme != "https" or not parts[2]:
                raise Invalid("Invalid base remote reference")
        elif kind == "FINAL":
            if len(parts) != 2 or not parts[1]:
                raise Invalid("Invalid final rule")
        elif kind == "GEOIP":
            if len(parts) != 3 or not re.fullmatch(r"[A-Z]{2}", parts[1]) or not parts[2]:
                raise Invalid("Invalid GEOIP rule")
        else:
            rule(line, policy_column=True)
    return result


def chatgpt(text):
    chunks = re.split(r"(?m)^#\s*>\s*", text)
    chosen = [c.split("\n", 1)[1] for c in chunks[1:]
              if c.split("\n", 1)[0].strip() == "ChatGPT"]
    if len(chosen) != 1:
        raise Invalid("Expected one ChatGPT section")
    return rules(chosen[0])


class Blocks(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.pre = None
        self.blocks = []
        self.inbound = False
        self.inbound_count = 0
        self.saw_outbound = False
        self.code = None
        self.ip_codes = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "pre":
            self.pre = []
        if tag == "h2":
            self.inbound = attrs.get("id") == "inbound-ip-addresses"
            self.inbound_count += int(self.inbound)
            self.saw_outbound |= attrs.get("id") == "outbound-ip-addresses"
        if tag == "code" and self.inbound:
            self.code = []

    def handle_data(self, data):
        if self.pre is not None:
            self.pre.append(data)
        if self.code is not None:
            self.code.append(data)

    def handle_endtag(self, tag):
        if tag == "pre" and self.pre is not None:
            self.blocks.append("".join(self.pre))
            self.pre = None
        if tag == "code" and self.code is not None:
            self.ip_codes.append("".join(self.code).strip())
            self.code = None


def claude(text):
    page = Blocks()
    page.feed(text)
    chosen = [b for b in page.blocks
              if any(s == "DOMAIN-SUFFIX,anthropic.com" for s in lines(b))]
    if len(chosen) != 1:
        raise Invalid("Expected one Claude typed-text block")
    parsed = rules(chosen[0])
    domains = [r for r in parsed if r.kind.startswith("DOMAIN")]
    if not domains:
        raise Invalid("Empty Claude domain block")
    return domains


def inbound(text, approved):
    page = Blocks()
    page.feed(text)
    if page.inbound_count != 1 or not page.saw_outbound:
        raise Invalid("Claude inbound section structure changed")
    networks = []
    for code in page.ip_codes:
        try:
            networks.append(str(ipaddress.ip_network(code)))
        except ValueError as e:
            raise Invalid("Unrecognized content in inbound code block") from e
    if sorted(networks) != sorted(approved):
        raise Invalid("Official Claude inbound ranges changed; review required")
    return [rule(f"IP-CIDR,{n},no-resolve") for n in networks]


def decode(data):
    if not data or len(data) > 20_000_000:
        raise Invalid("Empty or oversized download")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise Invalid("Source is not UTF-8") from e
    if not text.strip() or "\x00" in text:
        raise Invalid("Empty or binary source")
    return text
