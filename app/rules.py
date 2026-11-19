"""Allow-list rule model: host, ports and IPv4 networks.

A rule matches a CONNECT target only when *all three* dimensions match:

* the target host equals the rule host, is a subdomain of a ``*.`` wildcard
  host, or equals an IP-literal rule host;
* the target port is listed in ``ports``;
* every IPv4 address the proxy resolved for the host is inside one of the
  rule's networks.

The last point is deliberately strict: a rule is the unit of admission, so a
single rule must cover the host, the port and *all* of the resolved addresses.
This prevents a mixed DNS answer from smuggling an out-of-policy address into
a connection.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable

MAX_RULES = 500
MAX_PORTS_PER_RULE = 1024
MAX_NETWORKS_PER_RULE = 256
MAX_DESCRIPTION = 200

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class RuleValidationError(ValueError):
    """Raised with a list of human-readable problems."""

    def __init__(self, problems: Iterable[str]):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems) if self.problems else "invalid rules")


def _normalize_domain(value: str, *, where: str, allow_wildcard: bool) -> str:
    host = value.strip().lower()
    if not host:
        raise ValueError(f"{where}: host must not be empty")
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise ValueError(f"{where}: host must not be empty")

    if any(ch.isspace() for ch in host):
        raise ValueError(f"{where}: host must not contain whitespace")

    if "*" in host:
        if not allow_wildcard:
            raise ValueError(f"{where}: wildcards are not allowed in a CONNECT target")
        if not host.startswith("*.") or host.count("*") != 1:
            raise ValueError(f"{where}: the only supported wildcard form is '*.example.com'")
        suffix = host[2:]
        _validate_domain_labels(suffix, where)
        try:
            ipaddress.IPv4Address(suffix)
        except ValueError:
            return "*." + suffix
        raise ValueError(f"{where}: a wildcard cannot be used with an IP address")

    _validate_domain_labels(host, where)
    return host


def _validate_domain_labels(host: str, where: str) -> None:
    if len(host) > 253:
        raise ValueError(f"{where}: domain name is longer than 253 characters")
    if ":" in host:
        raise ValueError(f"{where}: IPv6 is not supported, only IPv4 networks")
    labels = host.split(".")
    if any(not label for label in labels):
        raise ValueError(f"{where}: domain name contains an empty label")
    for label in labels:
        if len(label) > 63:
            raise ValueError(f"{where}: label {label!r} is longer than 63 characters")
        if not _LABEL_RE.match(label):
            raise ValueError(
                f"{where}: label {label!r} must contain only letters, digits and hyphens, "
                "and must not start or end with a hyphen"
            )


def normalize_rule_host(value: str, *, where: str = "host") -> str:
    """Normalize a rule's host pattern (domain, wildcard or IPv4 literal)."""

    if not isinstance(value, str):
        raise ValueError(f"{where}: host must be a string")
    raw = value.strip()
    if not raw:
        raise ValueError(f"{where}: host must not be empty")
    if raw.startswith("["):
        raise ValueError(f"{where}: IPv6 is not supported, only IPv4")
    try:
        return str(ipaddress.IPv4Address(raw))
    except ValueError:
        pass
    return _normalize_domain(raw, where=where, allow_wildcard=True)


def normalize_target_host(value: str, *, where: str = "target host") -> str:
    """Normalize the host part of a CONNECT authority.

    IP literals are kept as canonical dotted quads; hostnames are lowercased.
    Wildcards are rejected because a client may only connect to a concrete
    target.
    """

    if not isinstance(value, str):
        raise ValueError(f"{where}: must be a string")
    raw = value.strip()
    if not raw:
        raise ValueError(f"{where}: must not be empty")
    if raw.startswith("[") or "]" in raw:
        raise ValueError(f"{where}: IPv6 is not supported, only IPv4")
    if ":" in raw:
        raise ValueError(f"{where}: IPv6 is not supported, only IPv4")
    if any(ch.isspace() for ch in raw):
        raise ValueError(f"{where}: must not contain whitespace")
    try:
        return str(ipaddress.IPv4Address(raw))
    except ValueError:
        pass
    return _normalize_domain(raw, where=where, allow_wildcard=False)


def is_ipv4_literal(host: str) -> bool:
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return True


def normalize_port(value: Any, *, where: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{where}: must be an integer between 1 and 65535")
    if isinstance(value, str):
        text = value.strip()
        if not text.isdigit():
            raise ValueError(f"{where}: must be an integer between 1 and 65535")
        value = int(text)
    if not isinstance(value, int):
        raise ValueError(f"{where}: must be an integer between 1 and 65535")
    if not 1 <= value <= 65535:
        raise ValueError(f"{where}: must be between 1 and 65535")
    return value


def _normalize_network(value: Any, *, where: str) -> ipaddress.IPv4Network:
    if not isinstance(value, str):
        raise ValueError(f"{where}: network must be a string such as '10.0.0.0/8'")
    text = value.strip()
    if not text:
        raise ValueError(f"{where}: network must not be empty")
    if ":" in text:
        raise ValueError(f"{where}: IPv6 is not supported, only IPv4 networks")
    try:
        network = ipaddress.IPv4Network(text, strict=False)
    except ValueError as exc:
        raise ValueError(f"{where}: {exc}") from exc
    return network


def validate_rules(raw: Any) -> list[dict[str, Any]]:
    """Validate and normalize the whole rule set.

    Returns a JSON-serializable list of normalized rules. Raises
    :class:`RuleValidationError` containing every problem found.
    """

    if not isinstance(raw, list):
        raise RuleValidationError(["rules must be a JSON array"])
    if len(raw) > MAX_RULES:
        raise RuleValidationError([f"at most {MAX_RULES} rules are allowed"])

    normalized: list[dict[str, Any]] = []
    problems: list[str] = []

    for index, item in enumerate(raw):
        where = f"rules[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{where}: each rule must be a JSON object")
            continue

        unknown = set(item) - {"host", "ports", "networks", "description"}
        if unknown:
            problems.append(f"{where}: unknown fields: {', '.join(sorted(unknown))}")

        try:
            host = normalize_rule_host(item.get("host"), where=f"{where}.host")
        except ValueError as exc:
            problems.append(str(exc))
            host = ""

        ports_raw = item.get("ports")
        ports: list[int] = []
        if not isinstance(ports_raw, list) or not ports_raw:
            problems.append(f"{where}.ports: must be a non-empty array of ports")
        elif len(ports_raw) > MAX_PORTS_PER_RULE:
            problems.append(f"{where}.ports: at most {MAX_PORTS_PER_RULE} ports are allowed")
        else:
            seen: set[int] = set()
            for port_index, port_raw in enumerate(ports_raw):
                try:
                    port = normalize_port(port_raw, where=f"{where}.ports[{port_index}]")
                except ValueError as exc:
                    problems.append(str(exc))
                    continue
                if port not in seen:
                    seen.add(port)
                    ports.append(port)
            if not ports and ports_raw:
                # Every entry failed; individual problems were already added.
                pass
            ports.sort()

        networks_raw = item.get("networks")
        networks: list[str] = []
        if not isinstance(networks_raw, list) or not networks_raw:
            problems.append(f"{where}.networks: must be a non-empty array of IPv4 CIDRs")
        elif len(networks_raw) > MAX_NETWORKS_PER_RULE:
            problems.append(
                f"{where}.networks: at most {MAX_NETWORKS_PER_RULE} networks are allowed"
            )
        else:
            seen_nets: set[str] = set()
            for net_index, net_raw in enumerate(networks_raw):
                try:
                    network = _normalize_network(
                        net_raw, where=f"{where}.networks[{net_index}]"
                    )
                except ValueError as exc:
                    problems.append(str(exc))
                    continue
                text = str(network)
                if text not in seen_nets:
                    seen_nets.add(text)
                    networks.append(text)

        description_raw = item.get("description", "")
        description = ""
        if description_raw is None:
            description_raw = ""
        if not isinstance(description_raw, str):
            problems.append(f"{where}.description: must be a string")
        elif len(description_raw.strip()) > MAX_DESCRIPTION:
            problems.append(
                f"{where}.description: at most {MAX_DESCRIPTION} characters are allowed"
            )
        else:
            description = description_raw.strip()

        normalized.append(
            {
                "host": host,
                "ports": ports,
                "networks": networks,
                "description": description,
            }
        )

    if problems:
        raise RuleValidationError(problems)
    return normalized


def _host_matches(pattern: str, host: str) -> bool:
    if is_ipv4_literal(pattern):
        return host == pattern
    if is_ipv4_literal(host):
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith("." + suffix)
    return host == pattern


@dataclass(frozen=True, slots=True)
class Rule:
    index: int  # 1-based position inside the committed revision
    host: str
    ports: frozenset[int]
    networks: tuple[ipaddress.IPv4Network, ...]
    description: str = ""

    @classmethod
    def from_normalized(cls, index: int, data: dict[str, Any]) -> "Rule":
        return cls(
            index=index,
            host=data["host"],
            ports=frozenset(data["ports"]),
            networks=tuple(ipaddress.IPv4Network(net) for net in data["networks"]),
            description=data.get("description", ""),
        )

    def matches_host(self, host: str) -> bool:
        return _host_matches(self.host, host)

    def permits_address(self, address: ipaddress.IPv4Address) -> bool:
        return any(address in network for network in self.networks)

    def to_api(self) -> dict[str, Any]:
        return {
            "id": self.index,
            "host": self.host,
            "ports": sorted(self.ports),
            "networks": [str(network) for network in self.networks],
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class RuleSetSnapshot:
    """One immutable, committed version of the whole rule set."""

    revision: int
    created_at: str
    note: str
    rules: tuple[Rule, ...]

    def candidates(self, host: str, port: int) -> tuple[Rule, ...]:
        """Rules that cover this host and port, before any address is known.

        Used to reject obviously disallowed targets without a DNS lookup.
        """

        return tuple(
            rule for rule in self.rules if port in rule.ports and rule.matches_host(host)
        )

    def admit(
        self, host: str, port: int, addresses: Iterable[str]
    ) -> "AdmissionDecision":
        parsed: list[ipaddress.IPv4Address] = []
        for raw in addresses:
            try:
                parsed.append(ipaddress.IPv4Address(raw))
            except ValueError:
                return AdmissionDecision(
                    allowed=False,
                    reason="non_ipv4_address",
                    detail=f"resolver returned a non-IPv4 address: {raw!r}",
                )

        candidates = list(self.candidates(host, port))
        if not candidates:
            return AdmissionDecision(
                allowed=False,
                reason="no_rule",
                detail=f"no committed rule allows {host}:{port}",
            )

        for rule in candidates:
            if all(rule.permits_address(address) for address in parsed):
                return AdmissionDecision(
                    allowed=True,
                    reason="allowed",
                    rule=rule,
                    detail=f"rule #{rule.index} permits {host}:{port}",
                )

        not_permitted = []
        for address in parsed:
            if not any(rule.permits_address(address) for rule in candidates):
                not_permitted.append(str(address))
        if not_permitted:
            detail = "resolved addresses outside the rule's networks: " + ", ".join(
                not_permitted
            )
        else:
            detail = (
                "resolved addresses are split across rules; one rule must permit all of "
                + ", ".join(str(address) for address in parsed)
            )
        return AdmissionDecision(
            allowed=False,
            reason="address_not_allowed",
            detail=detail,
        )

    def to_api(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "created_at": self.created_at,
            "note": self.note,
            "rules": [rule.to_api() for rule in self.rules],
        }


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    allowed: bool
    reason: str
    rule: Rule | None = None
    detail: str = ""


def build_snapshot(
    revision: int,
    created_at: str,
    note: str,
    normalized_rules: list[dict[str, Any]],
) -> RuleSetSnapshot:
    rules = tuple(
        Rule.from_normalized(index, data) for index, data in enumerate(normalized_rules, 1)
    )
    return RuleSetSnapshot(revision=revision, created_at=created_at, note=note, rules=rules)
