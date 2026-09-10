"""Frozen policy plus selected upstream data produces one standalone file."""
from collections import Counter
import fnmatch
import ipaddress
import json

from . import parse
from .parse import Invalid, Rule
from .fetch import digest


GROUPS = {"常规境外": "V3（vless+vision+reality）", "OpenAI": "V3 Static Residential",
          "Claude": "V3 Static Residential"}
UPDATE_URL = "https://raw.githubusercontent.com/ardingh/rillmoss/main/rillmoss.conf"
THS = ["10jqka.com.cn", "hexin.cn"] + [f"{x}.10jqka.com.cn" for x in
       ("data", "t", "news", "q", "basic", "moni", "upass", "user", "search", "5188.money")]


def canonical(data):
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def parse_sources(raw, manifest, personal):
    parsed, counts = {}, {}
    for source in manifest["sources"]:
        sid, fmt = source["id"], source["format"]
        text = parse.decode((raw / (sid + ".txt")).read_bytes())
        try:
            if fmt == "base":
                result = parse.sections(text)
                count = len(result["Rule"])
            elif fmt == "chatgpt":
                result = parse.chatgpt(text)
                count = len(result)
            elif fmt == "claude":
                result = parse.claude(text)
                count = len(result)
            elif fmt == "inbound":
                result = parse.inbound(text, personal["claude_inbound"])
                count = len(result)
            elif fmt == "rules":
                result = parse.rules(text, policy_column="/QuantumultX/" in source.get("path", ""))
                count = len(result)
            else:
                raise Invalid("Unknown source format")
        except Invalid as e:
            raise Invalid(f"{sid}: {e}") from e
        parsed[sid], counts[sid] = result, count
    return parsed, counts


def check_counts(counts, baseline):
    if baseline is None:
        raise Invalid("A reviewed count baseline is required")
    if set(counts) != set(baseline):
        raise Invalid("Source inventory differs from reviewed baseline")
    for sid, count in counts.items():
        old = baseline[sid]
        if not isinstance(old, int) or old <= 0 or count <= 0:
            raise Invalid(f"{sid}: invalid count baseline")
        if count * 5 < old * 4 or count * 2 > old * 3:
            raise Invalid(f"{sid}: abnormal rule count {old} -> {count}; review required")


def compose(parsed, manifest, personal):
    entries, seen, duplicates, removed = [], {}, [], []

    def add(r, policy, origin, required=False):
        # Parent-domain compaction is intentionally absent: THS keeps all 12 rows.
        if r in seen:
            duplicates.append(dict(rule=f"{r.kind},{r.value}", kept=seen[r], removed=origin))
            if required:
                raise Invalid("Duplicate required personal rule")
            return
        seen[r] = origin
        entries.append((r, policy, origin))

    add(Rule("DOMAIN", "humb.apple.com"), "DIRECT", "R01")
    # AI first; broad Apple/China sources must not override shared dependencies.
    for sid in ("openai-base", "openai-acl", "claude-page", "claude-ips"):
        for r in parsed[sid]:
            if r.value == "humb.apple.com":
                removed.append(dict(source=sid, rule=r.value, reason="Apple DIRECT exception"))
                continue
            add(r, "OpenAI" if sid.startswith("openai") else "Claude", sid)
    for domain in personal["apple_sync"]:
        add(Rule("DOMAIN-SUFFIX", domain), "DIRECT", "R01", required=True)
    for domain in personal["tonghuashun"]:
        add(Rule("DOMAIN-SUFFIX", domain), "DIRECT", "R03", required=True)
    add(Rule("DOMAIN-KEYWORD", "apimg.qunliao.info"), "REJECT", "R04", required=True)
    add(Rule("DOMAIN-SUFFIX", "bytedapm.com"), "常规境外", "TikTok exception", required=True)
    add(Rule("DOMAIN-SUFFIX", "snssdk.com"), "DIRECT", "DouYin exception", required=True)
    for row in manifest["base_order"]:
        if "source" in row:
            sid = row["source"]
            if sid == "openai-base":
                continue
            for r in parsed[sid]:
                if row["policy"] != "DIRECT" and (r.value == "snssdk.com" or r.value.endswith(".snssdk.com")):
                    removed.append(dict(source=sid, rule=r.value, reason="DouYin DIRECT exception"))
                    continue
                add(r, row["policy"], sid)
        else:
            parts = row["rule"].split(",")
            if parts[0] in {"GEOIP", "FINAL"}:
                continue
            add(parse.rule(",".join(parts[:2])), parts[2], "base-inline")
    return entries, duplicates, removed


def match_domain(rule, host):
    kind, value = rule.kind, rule.value
    if kind == "DOMAIN":
        return host == value
    if kind == "DOMAIN-SUFFIX":
        return host == value or host.endswith("." + value)
    if kind == "DOMAIN-KEYWORD":
        return value in host
    if kind == "DOMAIN-WILDCARD":
        return fnmatch.fnmatchcase(host, value)
    return False


def route(entries, host=None, address=None):
    ip = ipaddress.ip_address(address) if address else None
    for r, policy, origin in entries:
        if host and match_domain(r, host.lower()):
            return policy, origin, r.value
        if ip and r.kind in {"IP-CIDR", "IP-CIDR6"} and ip in ipaddress.ip_network(r.value):
            return policy, origin, r.value
    return "常规境外", "FINAL", "FINAL"


def constraints(entries, personal, parsed):
    if personal["groups"] != GROUPS or personal["update_url"] != UPDATE_URL:
        raise Invalid("Exact group binding or update URL violated")
    if personal["tonghuashun"] != THS:
        raise Invalid("The original twelve Tonghuashun rules must remain")
    settings = personal["sections"]
    general = dict(tuple(x.strip() for x in line.split("=", 1)) for line in settings["General"])
    for key, value in {"dns-direct-fallback-proxy": "true", "ipv6": "true", "prefer-ipv6": "false",
                       "udp-policy-not-supported-behaviour": "REJECT", "block-quic": "all-proxy",
                       "close-if-proxy-chain-missing": "true"}.items():
        if general.get(key) != value:
            raise Invalid(f"Required general setting violated: {key}")
    if settings["MITM"] != ["hostname = *.google.cn"] or settings["URL Rewrite"] != [
        "^https?://(www.)?g.cn https://www.google.com 302",
        "^https?://(www.)?google.cn https://www.google.com 302"]:
        raise Invalid("Google rewrite / MITM declaration changed")
    expected = {
        "chatgpt.com": "OpenAI", "api.openai.com": "OpenAI", "chatgpt.com/backend-api": "OpenAI",
        "cdn.oaistatic.com": "OpenAI", "files.oaiusercontent.com": "OpenAI",
        "auth0.com": "OpenAI", "api.statsig.com": "OpenAI", "sentry.io": "OpenAI",
        "claude.ai": "Claude", "api.anthropic.com": "Claude", "claudeusercontent.com": "Claude",
        "browser-intake-us5-datadoghq.com": "Claude", "api.sift.com": "Claude",
        "humb.apple.com": "DIRECT", "guzzoni.apple.com": "DIRECT", "smoot.apple.com": "DIRECT",
        "p01-ckdatabase.icloud.com": "DIRECT", "gateway.icloud.com": "DIRECT",
        "p01-ckdatabasews.icloud.com": "DIRECT", "p01-content.icloud-content.com": "DIRECT",
        "api.apple-cloudkit.com": "DIRECT", "courier.push.apple.com": "DIRECT",
        "apimg.qunliao.info": "REJECT",
        "bytedapm.com": "常规境外", "a.bytedapm.com": "常规境外", "snssdk.com": "DIRECT",
        "api.snssdk.com": "DIRECT", "www.bilibili.com": "DIRECT", "api.bilibili.com": "DIRECT",
        "github.com": "常规境外", "registry.npmjs.org": "常规境外", "www.google.com": "常规境外",
        "weixin.qq.com": "DIRECT", "www.zhihu.com": "DIRECT", "www.douban.com": "DIRECT",
    }
    expected.update({d: "DIRECT" for d in THS})
    results = []
    actual, origin, value = route(entries, host="img.dongqiudi.com")
    if actual == "REJECT":
        raise Invalid("Dongqiudi normal-image domain rejected")
    results.append(dict(target="img.dongqiudi.com", expected="not REJECT (GeoIP needs device resolution)",
                        actual=actual, source=origin, matched=value))
    for domain, policy in expected.items():
        host = domain.split("/", 1)[0]
        actual, origin, value = route(entries, host=host)
        results.append(dict(target=domain, expected=policy, actual=actual, source=origin, matched=value))
        if actual != policy:
            raise Invalid(f"Routing constraint failed: {domain}: {actual}, expected {policy}")
    for address in ("160.79.104.1", "2607:6bc0::1"):
        actual, origin, value = route(entries, address=address)
        if actual != "Claude":
            raise Invalid("Claude inbound IP constraint failed")
        results.append(dict(target=address, actual=actual, expected="Claude", source=origin, matched=value))
    for r in parsed["bilibili"]:
        if r.kind in {"DOMAIN", "DOMAIN-SUFFIX"} and route(entries, host=r.value)[0] != "DIRECT":
            raise Invalid("BiliBili domain is shadowed by a proxy rule")
        if r.kind in {"IP-CIDR", "IP-CIDR6"}:
            address = str(ipaddress.ip_network(r.value).network_address)
            if route(entries, address=address)[0] != "DIRECT":
                raise Invalid("BiliBili IP range is shadowed by a proxy rule")
    # Every source AI rule survives with an AI policy; exact cross-group duplicates use OpenAI.
    by_rule = {r: p for r, p, _ in entries}
    for sid in ("openai-base", "openai-acl", "claude-page", "claude-ips"):
        for r in parsed[sid]:
            if r.value == "humb.apple.com":
                continue
            if by_rule.get(r) not in {"OpenAI", "Claude"}:
                raise Invalid("AI source rule lost its residential policy")
            # A synthetic subdomain also catches broader earlier DIRECT/foreign matches.
            if r.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
                probe = "check." + r.value if r.kind == "DOMAIN-SUFFIX" else r.value
                if route(entries, host=probe)[0] not in {"OpenAI", "Claude"}:
                    raise Invalid("AI domain shadowed by an earlier non-residential rule")
    # Counts alone do not catch the loss of a single important known endpoint.
    if not personal["required_ai_targets"]:
        raise Invalid("Known AI endpoint guard must not be empty")
    for target in personal["required_ai_targets"]:
        if route(entries, host=target)[0] not in {"OpenAI", "Claude"}:
            raise Invalid(f"Known AI endpoint lost its residential route: {target}")
    return results


def render(entries, personal):
    blocks = ["# rillmoss / 溪苔 — 设备验收状态见 policy/release.json",
              "# 静态检查不证明未知端点或设备故障行为。节点连接参数由设备管理。",
              "[General]", f"update-url = {personal['update_url']}", *personal["sections"]["General"],
              "", "[Proxy Group]"]
    for group, node in GROUPS.items():
        blocks.append(f"{group} = select,{node},policy-select-name={node}")
    blocks.extend(["", "[Rule]"])
    previous = None
    for r, policy, origin in entries:
        if origin != previous:
            blocks.append(f"# {origin}")
            previous = origin
        blocks.append(r.render(policy))
    blocks.extend(["GEOIP,CN,DIRECT", "FINAL,常规境外"])
    for section in ("Host", "URL Rewrite", "MITM"):
        blocks.extend(["", f"[{section}]", *personal["sections"][section]])
    body = "\n".join(blocks) + "\n"
    version = digest(body.encode())
    return f"# rules-version: {version}\n{body}", version


def build(raw, manifest, personal, baseline):
    parsed, counts = parse_sources(raw, manifest, personal)
    check_counts(counts, baseline)
    entries, duplicates, removed = compose(parsed, manifest, personal)
    checks = constraints(entries, personal, parsed)
    conf, version = render(entries, personal)
    actual_sections = parse.sections(conf)
    if any(x in conf for x in ("RULE-SET,", "DOMAIN-SET,", "[Proxy]", "private-key", "password=")):
        raise Invalid("Remote rule dependency or proxy credentials in generated configuration")
    if len(actual_sections["Proxy Group"]) != 3:
        raise Invalid("Expected exactly three groups")
    drift = {}
    approved = personal["base_sections_approved"]
    for name in sorted(set(parsed["base"]) | set(approved)):
        if parsed["base"].get(name) != approved.get(name):
            drift[name] = dict(added=[s for s in parsed["base"].get(name, []) if s not in approved.get(name, [])],
                               removed=[s for s in approved.get(name, []) if s not in parsed["base"].get(name, [])])
    report = dict(schema=1, rules_version=version, source_counts=counts, rule_count=len(entries) + 2,
                  policy_counts=dict(Counter(p for _, p, _ in entries)), checks=checks,
                  duplicate_count=len(duplicates), duplicates=duplicates, removed=removed,
                  base_changes_not_imported=drift, device_acceptance="pending; static checks only")
    return conf, report
