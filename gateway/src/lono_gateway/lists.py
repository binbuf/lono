"""Load per-category replacement lists from files, with built-in fallbacks.

Users can point any category at their own text file (one value per line,
``#`` comments allowed) via ``pseudonymization.lists``; inline
``pseudonymization.pools`` values override both.
"""

from __future__ import annotations

import logging
from pathlib import Path

from lono_gateway.pools import DEFAULT_LISTS, Pools
from lono_gateway.settings import PseudonymizationConfig

logger = logging.getLogger(__name__)


def parse_list_text(text: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key = line.casefold()
        if key in seen:
            continue
        seen.add(key)
        values.append(line)
    return values


def resolve_list_file(spec: str, lists_dir: str) -> Path | None:
    if not spec or spec.strip().lower() in {"builtin", "default"}:
        return None
    repo_root = Path(__file__).resolve().parents[3]
    spec_path = Path(spec)
    candidates: list[Path] = []
    if spec_path.is_absolute():
        candidates.append(spec_path)
    else:
        candidates.append(Path(lists_dir) / spec)
        if lists_dir.startswith(("/", "\\")):
            # Local dev without the container's /config mount.
            candidates.append(repo_root / lists_dir.lstrip("/\\") / spec)
        candidates.append(repo_root / spec)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    logger.warning("configured list file not found (tried %s)", ", ".join(str(c) for c in candidates))
    return None


def build_lists(cfg: PseudonymizationConfig) -> dict[str, list[str]]:
    """Resolve every configured list.

    ``DEFAULT_LISTS`` names have shipped fallbacks. Any *additional* name may
    be supplied too — e.g. a list named ``PHONE_NUMBER`` or ``CUSTOMER_ID`` —
    and it becomes a literal replacement pool for that category.
    """
    resolved: dict[str, list[str]] = {}
    configured = {name for name, spec in (cfg.lists or {}).items() if spec}
    for name in sorted(set(DEFAULT_LISTS) | configured):
        builtin = DEFAULT_LISTS.get(name, [])
        spec = (cfg.lists or {}).get(name, "")
        path = resolve_list_file(spec, cfg.lists_dir or "")
        values: list[str] = []
        if path is not None:
            try:
                values = parse_list_text(path.read_text(encoding="utf-8"))
            except OSError as exc:
                logger.warning("could not read list %s for %s: %s", path, name, exc)
        if not values and builtin:
            values = list(builtin)
        if not values:
            logger.warning("list %r resolved to no values; category will be generated instead", name)
            continue
        resolved[name] = values
    return resolved


def build_pools(cfg: PseudonymizationConfig) -> Pools:
    return Pools.from_config(cfg.pools, build_lists(cfg))