"""Runtime configuration, loaded from environment variables."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise SystemExit(f"{name} must be positive")
    return value


def _int_env(name: str, default: int, *, minimum: int = 1, maximum: int = 65535) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise SystemExit(f"{name} must be between {minimum} and {maximum}")
    return value


def default_bootstrap_rules(demo_host: str, demo_port: int, demo_cidr: str) -> tuple[dict, ...]:
    """A single rule that makes the bundled demo reachable out of the box."""

    return (
        {
            "host": demo_host,
            "ports": [demo_port],
            "networks": [demo_cidr],
        },
    )


@dataclass(frozen=True, slots=True)
class Settings:
    db_path: str = "data/proxy.db"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 3128
    web_host: str = "0.0.0.0"
    web_port: int = 8000
    # Time allowed for DNS lookups / TCP dials / reading the CONNECT header.
    dns_timeout: float = 3.0
    connect_timeout: float = 5.0
    header_timeout: float = 5.0
    # A tunnel with no traffic in either direction for this long is closed.
    idle_timeout: float = 120.0
    max_header_bytes: int = 8192
    test_connect_timeout: float = 8.0
    # Bundled demo service, used for the test-connect button and bootstrap rule.
    demo_host: str = "127.0.0.1"
    demo_port: int = 8080
    demo_cidr: str = "127.0.0.0/8"
    bootstrap_rules: tuple[dict, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls) -> "Settings":
        demo_host = os.environ.get("DEMO_HOST", "127.0.0.1").strip()
        demo_port = _int_env("DEMO_PORT", 8080)
        demo_cidr = os.environ.get("DEMO_CIDR", "127.0.0.0/8").strip()

        raw_bootstrap = os.environ.get("BOOTSTRAP_RULES_JSON")
        if raw_bootstrap is None or raw_bootstrap.strip() == "":
            bootstrap = default_bootstrap_rules(demo_host, demo_port, demo_cidr)
        else:
            try:
                parsed = json.loads(raw_bootstrap)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"BOOTSTRAP_RULES_JSON is not valid JSON: {exc}") from exc
            if not isinstance(parsed, list):
                raise SystemExit("BOOTSTRAP_RULES_JSON must be a JSON array of rules")
            bootstrap = tuple(parsed)

        return cls(
            db_path=os.environ.get("APP_DB_PATH", "data/proxy.db"),
            proxy_host=os.environ.get("PROXY_HOST", "0.0.0.0"),
            proxy_port=_int_env("PROXY_PORT", 3128, minimum=1, maximum=65535),
            web_host=os.environ.get("WEB_HOST", "0.0.0.0"),
            web_port=_int_env("WEB_PORT", 8000, minimum=1, maximum=65535),
            dns_timeout=_float_env("DNS_TIMEOUT", 3.0),
            connect_timeout=_float_env("CONNECT_TIMEOUT", 5.0),
            header_timeout=_float_env("HEADER_TIMEOUT", 5.0),
            idle_timeout=_float_env("IDLE_TIMEOUT", 120.0),
            max_header_bytes=_int_env("MAX_HEADER_BYTES", 8192, minimum=512, maximum=1_048_576),
            test_connect_timeout=_float_env("TEST_CONNECT_TIMEOUT", 8.0),
            demo_host=demo_host,
            demo_port=demo_port,
            demo_cidr=demo_cidr,
            bootstrap_rules=bootstrap,
        )
