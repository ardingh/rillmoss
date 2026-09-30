"""Check direct-route intent independently of counts and duplicate removal."""
from collections import defaultdict
import fnmatch
import ipaddress

from .parse import Invalid, Rule, rule


class DomainRoutes:
    def __init__(self, entries):
        self.exact = defaultdict(list)
        self.suffix = defaultdict(list)
        self.patterns = []
        for index, entry in enumerate(entries):
            r = entry[0]
            item = (index, entry)
            if r.kind == "DOMAIN":
                self.exact[r.value].append(item)
            elif r.kind == "DOMAIN-SUFFIX":
                self.suffix[r.value].append(item)
            elif r.kind in {"DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}:
                self.patterns.append(item)

    def match(self, host):
        host = host.lower()
        candidates = list(self.exact.get(host, ()))
        labels = host.split(".")
        for index in range(len(labels)):
            candidates.extend(self.suffix.get(".".join(labels[index:]), ()))
        for item in self.patterns:
            r = item[1][0]
            if ((r.kind == "DOMAIN-KEYWORD" and r.value in host)
                    or (r.kind == "DOMAIN-WILDCARD" and fnmatch.fnmatchcase(host, r.value))):
                candidates.append(item)
        return min(candidates, key=lambda x: x[0])[1] if candidates else None


def domain_probes(r):
    if r.kind == "DOMAIN":
        return [r.value]
    if r.kind == "DOMAIN-SUFFIX":
        return [r.value, "rillmoss-check." + r.value]
    if r.kind == "DOMAIN-WILDCARD":
        return [r.value.replace("*", "rillmoss-check").replace("?", "a")]
    if r.kind == "DOMAIN-KEYWORD":
        return ["rillmoss-check-" + r.value + ".example"]
    return []


def conflict(source, expected_rule, winner):
    r, policy, origin = winner
    return dict(source=source, rule=expected_rule.render("DIRECT"),
                actual=policy, matched=r.render(policy), origin=origin)


def identity(row):
    return tuple(row[k] for k in ("source", "rule", "actual", "matched", "origin"))


def observe(entries, parsed, manifest, personal):
    """Return actual cross-policy matches; never derive authorization from upstream."""
    routes = DomainRoutes(entries)
    conflicts, checks = {}, []

    def observe_domain(source, r, host, required=False):
        winner = routes.match(host)
        if required:
            checks.append(dict(target=host, expected="DIRECT",
                               actual=winner[1] if winner else "unmatched",
                               source=winner[2] if winner else "IP/GeoIP/FINAL",
                               matched=winner[0].value if winner else None))
        if winner and winner[1] != "DIRECT":
            row = conflict(source, r, winner)
            conflicts[identity(row)] = row
        elif winner is None:
            raise Invalid(f"Required DIRECT target has no domain route: {host}")

    settings = personal["direct_routing"]
    groups = settings["domestic_targets"]
    if set(groups) != set(personal["domestic_apps"]) or any(not hosts for hosts in groups.values()):
        raise Invalid("Every domestic app must have reviewed direct-route targets")
    required = [rule(text) for text in settings["priority_rules"]]
    if not required:
        raise Invalid("Direct priority-rule inventory must not be empty")
    for r in required:
        for host in domain_probes(r):
            observe_domain("personal-direct", r, host, required=True)
    for app, hosts in groups.items():
        for host in hosts:
            r = rule("DOMAIN-SUFFIX," + host)
            observe_domain("domestic:" + app, r, host, required=True)
            observe_domain("domestic:" + app, r, "rillmoss-check." + host, required=True)
            required.append(r)

    # Probe proxy children as well as the protected parent. Checking only
    # cmbchina.com would miss an added DOMAIN,login.cmbchina.com,Overseas.
    for source in manifest["base_order"]:
        if source.get("policy") != "DIRECT":
            continue
        for r in parsed[source["source"]]:
            # The generic CN suffix is a fallback, not a decision to override
            # every explicit overseas service using a .cn domain.
            if r == Rule("DOMAIN-SUFFIX", "cn"):
                continue
            hosts = domain_probes(r)
            if hosts and all((winner := routes.match(host)) and winner[1] == "DIRECT" for host in hosts):
                required.append(r)
    protected = DomainRoutes([(r, "DIRECT", "personal-direct") for r in required])
    for r, policy, origin in entries:
        if policy == "DIRECT":
            continue
        for host in domain_probes(r):
            coverage = protected.match(host)
            winner = routes.match(host)
            if coverage and winner and winner[1] != "DIRECT":
                row = conflict("protected-subdomain", coverage[0], winner)
                conflicts[identity(row)] = row

    nets = [(ipaddress.ip_network(r.value), (r, policy, origin))
            for r, policy, origin in entries if r.kind in {"IP-CIDR", "IP-CIDR6"}]
    exact = {}
    for r, policy, origin in entries:
        exact.setdefault(r, (r, policy, origin))
    domain_count = 0
    for source in manifest["base_order"]:
        if source.get("policy") != "DIRECT":
            continue
        sid = source["source"]
        for r in parsed[sid]:
            hosts = domain_probes(r)
            domain_count += len(hosts)
            for host in hosts:
                observe_domain(sid, r, host)
            if r.kind in {"USER-AGENT", "URL-REGEX", "IP-ASN"}:
                winner = exact.get(r)
                if winner and winner[1] != "DIRECT":
                    row = conflict(sid, r, winner)
                    conflicts[identity(row)] = row
            if r.kind in {"IP-CIDR", "IP-CIDR6"}:
                network = ipaddress.ip_network(r.value)
                # Partition at every intersecting boundary to cover interior
                # subnets, including a new proxy range after a DIRECT range.
                points = {int(network.network_address)}
                end = int(network.broadcast_address)
                for net, _ in nets:
                    if net.version == network.version and net.overlaps(network):
                        points.add(max(int(net.network_address), int(network.network_address)))
                        if int(net.broadcast_address) < end:
                            points.add(int(net.broadcast_address) + 1)
                for point in sorted(points):
                    for net, winner in nets:
                        if net.version == network.version and int(net.network_address) <= point <= int(net.broadcast_address):
                            if winner[1] != "DIRECT":
                                row = conflict(sid, r, winner)
                                conflicts[identity(row)] = row
                            break
    return sorted(conflicts.values(), key=identity), checks, domain_count


def validate(entries, parsed, manifest, personal):
    actual, checks, domain_count = observe(entries, parsed, manifest, personal)
    allowed = personal["direct_routing"]["reviewed_conflicts"]
    approved = {}
    for row in allowed:
        if not row.get("reason") or identity(row) in approved or row["actual"] == "DIRECT":
            raise Invalid("Invalid or duplicate reviewed direct-route conflict")
        approved[identity(row)] = row
    unreviewed = [row for row in actual if identity(row) not in approved]
    if unreviewed:
        first = unreviewed[0]
        hint = "; Claude unchanged: review the conflicting target" if first["actual"] == "Claude" else ""
        raise Invalid(f"Unreviewed DIRECT routing conflict: {first['source']} {first['rule']}"
                      f" -> {first['matched']} ({first['origin']}){hint}")
    return dict(checked_source_domain_probes=domain_count,
                protected_priority_rules=len(personal["direct_routing"]["priority_rules"]),
                domestic_target_count=sum(map(len, personal["direct_routing"]["domestic_targets"].values())),
                conflicts=[dict(row, reason=approved[identity(row)]["reason"]) for row in actual],
                claude_conflicts=[row for row in actual if row["actual"] == "Claude"]), checks
