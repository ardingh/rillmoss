"""Derive a separately verifiable advertising variant from a validated base bundle."""
from collections import Counter
import copy
import ipaddress
from pathlib import Path
import re
import shutil

from . import build, fetch, guard, parse
from .parse import Invalid, Rule


OUTPUT = "rillmoss-ad.conf"
UPDATE_URL = "https://raw.githubusercontent.com/ardingh/rillmoss/main/" + OUTPUT
BUNDLE_PATHS = (OUTPUT, "adblock", "policy/adblock.json")
SOURCES = [
    dict(id="anti-ad", repo="privacy-protection-tools/anti-AD", ref="master",
         path="anti-ad-surge.txt", format="domain-suffix"),
    dict(id="anti-ad-license", repo="privacy-protection-tools/anti-AD", ref="master",
         path="LICENSE", format="license"),
]


def validate_policy(policy):
    if (set(policy) != {"schema", "sources", "update_url", "reviewed_count", "routing_priority"}
            or policy["schema"] != 1 or policy["sources"] != SOURCES
            or policy["update_url"] != UPDATE_URL
            or policy["routing_priority"] != "existing_routes_first"
            or type(policy["reviewed_count"]) is not int or policy["reviewed_count"] <= 0):
        raise Invalid("Advertising policy must retain the reviewed source, URL and base-route priority")


def parse_ads(data, baseline):
    rules = parse.rules(parse.decode(data))
    build.check_counts({"anti-ad": len(rules)}, {"anti-ad": baseline})
    for r in rules:
        if (r.kind != "DOMAIN-SUFFIX" or r.flags or len(r.value.split(".")) < 2
                or len(r.value) > 253
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                       for label in r.value.split("."))):
            raise Invalid("anti-AD must contain only literal domain-suffix rules")
    return rules


def derive(base, data, policy, license_data):
    from . import runner
    validate_policy(policy)
    base_conf, base_report = runner.verify(base)
    manifest = runner.read(base / "snapshot/inputs/sources.json")
    personal = runner.read(base / "snapshot/inputs/personal.json")
    parsed, _ = build.parse_sources(base / "snapshot/raw", manifest, personal)
    entries, _, _ = build.compose(parsed, manifest, personal)
    ads = parse_ads(data, policy["reviewed_count"])
    license_text = parse.decode(license_data)
    if not license_text.startswith("MIT License") or "Copyright (c)" not in license_text:
        raise Invalid("anti-AD license changed; review before redistribution")

    # Keep the complete personal prefix (including residential IP/keyword rules)
    # ahead of all new blocks. No probing approximation can move an ad before it.
    ordinary = {row["source"] for row in manifest["base_order"] if "source" in row} - {"openai-base"}
    boundary = next((i for i, (_, _, origin) in enumerate(entries)
                     if origin in ordinary or origin == "base-inline"), None)
    if boundary is None or any(p in {"Claude", "OpenAI", "Muse", "V3 Static Residential"}
                               for _, p, _ in entries[boundary:]):
        raise Invalid("Cannot locate a safe advertising insertion after all residential routes")

    routes = guard.DomainRoutes(entries)
    direct_rules = [parse.rule(text) for text in personal["direct_routing"]["priority_rules"]]
    direct_rules += [Rule("DOMAIN-SUFFIX", host)
                     for hosts in personal["direct_routing"]["domestic_targets"].values() for host in hosts]
    for row in manifest["base_order"]:
        if row.get("policy") != "DIRECT":
            continue
        for r in parsed[row["source"]]:
            hosts = guard.domain_probes(r)
            if (r != Rule("DOMAIN-SUFFIX", "cn") and hosts
                    and all((winner := routes.match(host)) and winner[1] == "DIRECT" for host in hosts)):
                direct_rules.append(r)
    direct_routes = guard.DomainRoutes([(r, "DIRECT", "protected-direct") for r in direct_rules])
    protected = {}
    probes = set()
    for r, _, _ in entries:
        if r == Rule("DOMAIN-SUFFIX", "cn"):
            continue  # CN is the geographic fallback, not a personal exception.
        probes.update(guard.domain_probes(r))
    for check in base_report["checks"]:
        host = check.get("target", "").split("/", 1)[0]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if host:
                probes.add(host)
    for host in sorted(probes):
        labels = host.split(".")
        for index in range(len(labels) - 1):
            protected.setdefault(".".join(labels[index:]), host)

    accepted, excluded, seen = [], [], set()
    for r in ads:
        if r in seen:
            excluded.append(dict(rule=r.render("REJECT"), reason="duplicate anti-AD rule"))
            continue
        seen.add(r)
        if r.value in protected:
            excluded.append(dict(rule=r.render("REJECT"), reason="existing routing target",
                                 target=protected[r.value]))
            continue
        direct = next((winner for host in guard.domain_probes(r)
                       if (winner := direct_routes.match(host))), None)
        if direct:
            excluded.append(dict(rule=r.render("REJECT"), reason="existing direct domain scope",
                                 matched=direct[0].render("DIRECT")))
            continue
        winner = routes.match(r.value)
        if winner and (winner[1] in {"Claude", "OpenAI", "Muse", "V3 Static Residential"}
                       or (winner[1] == "DIRECT" and winner[0] != Rule("DOMAIN-SUFFIX", "cn"))):
            excluded.append(dict(rule=r.render("REJECT"), reason="existing protected domain scope",
                                 matched=winner[0].render(winner[1]), origin=winner[2]))
            continue
        accepted.append((r, "REJECT", "anti-AD"))
    if not accepted:
        raise Invalid("anti-AD contributed no usable advertising rules")

    combined = entries[:boundary] + accepted + entries[boundary:]
    # Reuse every base constraint. New ad conflicts are removed from the ad list,
    # never added as exemptions to the base's reviewed routing conflicts.
    checks = build.constraints(combined, personal, parsed)
    direct_report, _ = guard.validate(combined, parsed, manifest, personal)
    if direct_report != base_report["direct_routing"]:
        raise Invalid("Advertising variant changed the base direct-routing protections")
    ad_routes = guard.DomainRoutes(combined)
    for host in sorted(probes):
        before, after = routes.match(host), ad_routes.match(host)
        if before != after:
            raise Invalid(f"Advertising rule changed an existing route: {host}")
    for r, _, _ in accepted:
        for host in guard.domain_probes(r):
            winner = ad_routes.match(host)
            if winner is None or winner[1] != "REJECT":
                raise Invalid(f"Advertising rule is ineffective: {host}")
    variant_personal = copy.deepcopy(personal)
    variant_personal["update_url"] = policy["update_url"]
    conf, _ = build.render(combined, variant_personal)
    # A downloaded standalone conf must carry the upstream notice too.
    notice = "# Source: https://github.com/privacy-protection-tools/anti-AD\n"
    notice += "".join(("# " + line.rstrip() if line.strip() else "#") + "\n"
                      for line in license_text.splitlines())
    body = conf.split("\n", 1)[1].replace("# anti-AD\n", "# anti-AD\n" + notice, 1)
    version = fetch.digest(body.encode())
    conf = f"# rules-version: {version}\n{body}"
    base_sections, variant_sections = parse.sections(base_conf), parse.sections(conf)
    for section in base_sections.keys() - {"Rule", "General"}:
        if variant_sections[section] != base_sections[section]:
            raise Invalid(f"Advertising variant changed base section: {section}")
    if variant_sections["General"] != [line.replace(build.UPDATE_URL, UPDATE_URL)
                                        for line in base_sections["General"]]:
        raise Invalid("Advertising variant changed base networking settings")
    base_rules = base_sections["Rule"]
    ad_rules = variant_sections["Rule"]
    if ad_rules[:boundary] + ad_rules[boundary + len(accepted):] != base_rules:
        raise Invalid("Advertising variant did not retain every base rule in order")
    return conf, dict(schema=1, rules_version=version, base_rules_version=base_report["rules_version"],
                      base_conf_sha256=fetch.digest(base_conf.encode()),
                      source_rule_count=len(ads), added_rule_count=len(accepted),
                      excluded_rule_count=len(excluded), excluded=excluded,
                      rule_count=len(combined) + 2,
                      policy_counts=dict(Counter(p for _, p, _ in combined)),
                      insertion_after_base_rules=boundary, checked_existing_hosts=len(probes),
                      checks=checks, direct_routing=direct_report,
                      device_acceptance="pending; static checks only")


def stage(root, base, output, collector=None):
    from . import runner
    if output.exists():
        raise Invalid("Advertising output must be a new directory")
    # Validate before contacting anti-AD. The base never depends on this source.
    runner.verify(base)
    policy = runner.read(root / "policy/adblock.json")
    validate_policy(policy)
    output.mkdir(parents=True)
    raw = output / "adblock/raw"
    if collector is None:
        metadata = fetch.collect(dict(sources=policy["sources"]), raw, require_base=False)
    else:
        metadata = collector(dict(sources=policy["sources"]), raw)
    for name in runner.BUNDLE_PATHS:
        src, dst = base / name, output / "adblock/base" / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    conf, report = derive(output / "adblock/base", (raw / "anti-ad.txt").read_bytes(), policy,
                          (raw / "anti-ad-license.txt").read_bytes())
    (output / OUTPUT).write_text(conf)
    runner.write(output / "adblock/inputs/policy.json", policy)
    successful = dict(policy, reviewed_count=report["source_rule_count"])
    runner.write(output / "policy/adblock.json", successful)
    runner.write(output / "adblock/report.json", report)
    current_path = root / "adblock/version.json"
    current = runner.read(current_path) if current_path.exists() else {}
    files = {str(p.relative_to(output)): fetch.digest(p.read_bytes())
             for p in output.rglob("*") if p.is_file()}
    snapshot_id = fetch.digest(build.canonical(dict(files=files, upstream=metadata)))
    runner.write(output / "adblock/manifest.json",
                 dict(schema=1, files=files, upstream=metadata, snapshot_id=snapshot_id,
                      checked_at=runner.utc()))
    runner.write(output / "adblock/version.json", dict(
        schema=1, rules_version=report["rules_version"], base_rules_version=report["base_rules_version"],
        snapshot_id=snapshot_id,
        rules_built_at=current.get("rules_built_at") if current.get("rules_version") == report["rules_version"] else runner.utc()))
    verify(output)
    return report


def verify(bundle):
    from . import runner
    meta = runner.read(bundle / "adblock/manifest.json")
    files = meta["files"]
    if fetch.digest(build.canonical(dict(files=files, upstream=meta["upstream"]))) != meta["snapshot_id"]:
        raise Invalid("Advertising snapshot manifest digest mismatch")
    required = {OUTPUT, "policy/adblock.json", "adblock/inputs/policy.json", "adblock/report.json",
                "adblock/raw/anti-ad.txt", "adblock/raw/anti-ad-license.txt"}
    base_meta = runner.read(bundle / "adblock/base/snapshot/manifest.json")
    required |= {"adblock/base/" + p for p in base_meta["files"]}
    required |= {"adblock/base/version.json", "adblock/base/snapshot/manifest.json"}
    actual = {str(p.relative_to(bundle)) for p in (bundle / "adblock").rglob("*") if p.is_file()}
    actual -= {"adblock/manifest.json", "adblock/version.json"}
    actual |= {OUTPUT, "policy/adblock.json"}
    if set(files) != required or actual != required:
        raise Invalid("Advertising snapshot is incomplete or contains unexpected files")
    for relative, checksum in files.items():
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or any((bundle / Path(*path.parts[:i])).is_symlink()
                                                         for i in range(1, len(path.parts) + 1)):
            raise Invalid("Unsafe advertising snapshot path")
        if fetch.digest((bundle / relative).read_bytes()) != checksum:
            raise Invalid(f"Advertising snapshot checksum mismatch: {relative}")
    policy = runner.read(bundle / "adblock/inputs/policy.json")
    validate_policy(policy)
    upstream = meta["upstream"]
    repo = SOURCES[0]["repo"].lower()
    if set(upstream["pins"]) != {repo} or set(upstream["sources"]) != {s["id"] for s in SOURCES}:
        raise Invalid("Advertising upstream inventory mismatch")
    pin = upstream["pins"][repo]
    if not re.fullmatch(r"[a-f0-9]{40}", pin):
        raise Invalid("Invalid anti-AD snapshot commit")
    for source in SOURCES:
        record = upstream["sources"][source["id"]]
        data = (bundle / "adblock/raw" / (source["id"] + ".txt")).read_bytes()
        url = f"https://raw.githubusercontent.com/{source['repo']}/{pin}/{source['path']}"
        if (record["commit"] != pin or record["url"] != url or record["sha256"] != fetch.digest(data)
                or record["bytes"] != len(data)):
            raise Invalid("anti-AD snapshot mixes commits or raw contents")
    conf, report = derive(bundle / "adblock/base", (bundle / "adblock/raw/anti-ad.txt").read_bytes(), policy,
                          (bundle / "adblock/raw/anti-ad-license.txt").read_bytes())
    if conf != (bundle / OUTPUT).read_text() or report != runner.read(bundle / "adblock/report.json"):
        raise Invalid("Advertising offline rebuild differs from stored bundle")
    if runner.read(bundle / "policy/adblock.json") != dict(policy, reviewed_count=report["source_rule_count"]):
        raise Invalid("Advertising count baseline mismatch")
    version = runner.read(bundle / "adblock/version.json")
    if (version["rules_version"] != report["rules_version"]
            or version["base_rules_version"] != report["base_rules_version"]
            or version["snapshot_id"] != meta["snapshot_id"]):
        raise Invalid("Advertising version record mismatch")
    return conf, report


def install(root, bundle, replace=None):
    from . import runner
    verify(bundle)
    if replace is None:
        runner.install_files(root, bundle, BUNDLE_PATHS)
    else:
        runner.install_files(root, bundle, BUNDLE_PATHS, replace)
