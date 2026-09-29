"""Deterministic synthetic value pools used for pseudonymization."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

FIRST_NAMES = [
    "Alex", "Bob", "Carol", "Dana", "Erik", "Fiona", "Grace", "Henry", "Irene", "Jack",
    "Karen", "Liam", "Mona", "Nadia", "Oscar", "Paula", "Quentin", "Rita", "Sam", "Tina",
    "Uma", "Victor", "Wendy", "Xavier", "Yara", "Zane", "Alice", "Bruno", "Cora", "Derek",
    "Elena", "Felix", "Gina", "Hugo", "Iris", "Jonas", "Kira", "Leo", "Maya", "Noah",
    "Olga", "Peter", "Rosa", "Simon", "Tessa", "Umar", "Vera", "Will", "Yvonne", "Zoe",
]

LAST_NAMES = [
    "Anderson", "Baker", "Carter", "Davis", "Evans", "Foster", "Garcia", "Hughes", "Irwin", "Jones",
    "Klein", "Lopez", "Miller", "Nelson", "Owens", "Parker", "Quinn", "Reed", "Santos", "Turner",
    "Underwood", "Vargas", "Walker", "Xu", "Young", "Zimmer", "Brooks", "Chen", "Diaz", "Ellis",
    "Fisher", "Grant", "Hayes", "Ivanov", "Jensen", "Khan", "Lewis", "Morgan", "Nguyen", "Ortega",
    "Patel", "Ramos", "Silva", "Thomas", "Ulrich", "Vega", "Wong", "Yamada", "Zhang", "Okafor",
]

CITIES = [
    "Springfield", "Riverton", "Fairview", "Lakeside", "Brookfield", "Cedar Falls", "Greenville",
    "Ashland", "Madison", "Clayton", "Dover", "Elmwood", "Franklin", "Georgetown", "Hampton",
    "Kingsport", "Lexington", "Milton", "Newport", "Oakdale", "Portsmouth", "Rockford",
    "Salem", "Trenton", "Utica", "Vienna", "Winchester", "Yorktown", "Bristol", "Coventry",
]

COMPANIES = [
    "Acme Corp", "Globex", "Initech", "Umbrella Systems", "Northwind Traders", "Contoso",
    "Fabrikam", "Litware", "Proseware", "Wide World Importers", "Adventure Works",
    "Blue Yonder", "Coho Vineyard", "Lucerne Publishing", "Margie Travel", "Nod Publishers",
    "Relecloud", "Southridge Video", "Tailspin Toys", "Trey Research", "VanArsdel",
    "Wingtip Toys", "Alpine Ski House", "City Power & Light", "Consolidated Messenger",
]

DOMAIN_WORDS = [
    "aurora", "basalt", "cobalt", "delta", "ember", "fjord", "granite", "harbor", "indigo",
    "juniper", "kestrel", "lantern", "meridian", "nimbus", "onyx", "prairie", "quarry",
    "ridge", "summit", "tundra", "umbra", "vertex", "willow", "xenon", "yarrow", "zephyr",
]

NATIONALITIES = [
    "Canadian", "Brazilian", "Norwegian", "Japanese", "Kenyan", "Portuguese", "Australian",
    "Mexican", "Polish", "Thai", "Dutch", "Argentine", "Finnish", "Moroccan", "Vietnamese",
]


@dataclass
class Pools:
    first_names: list[str] = field(default_factory=lambda: list(FIRST_NAMES))
    last_names: list[str] = field(default_factory=lambda: list(LAST_NAMES))
    cities: list[str] = field(default_factory=lambda: list(CITIES))
    companies: list[str] = field(default_factory=lambda: list(COMPANIES))
    domain_words: list[str] = field(default_factory=lambda: list(DOMAIN_WORDS))
    nationalities: list[str] = field(default_factory=lambda: list(NATIONALITIES))

    @classmethod
    def from_config(cls, overrides: dict[str, list[str]]) -> Pools:
        pools = cls()
        for key, values in (overrides or {}).items():
            if hasattr(pools, key) and isinstance(values, list) and values:
                setattr(pools, key, [str(v) for v in values])
        return pools


def _luhn_check_digit(digits: str) -> str:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 0:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return str((10 - total % 10) % 10)


def _hex(rng: random.Random, chars: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(chars))


def generate_pseudonym(kind: str, original: str, rng: random.Random, pools: Pools) -> str:
    """Generate a deterministic synthetic replacement for an entity span."""
    kind = (kind or "").upper()

    if kind in {"EMAIL_ADDRESS", "EMAIL"}:
        first = rng.choice(pools.first_names).lower()
        last = rng.choice(pools.last_names).lower()
        suffix = f"{rng.randint(1, 99)}" if rng.random() < 0.4 else ""
        return f"{first}.{last}{suffix}@example.com"

    if kind in {"PERSON", "PER"}:
        first = rng.choice(pools.first_names)
        if " " in original.strip():
            return f"{first} {rng.choice(pools.last_names)}"
        return first

    if kind in {"PHONE_NUMBER", "PHONE"}:
        return f"+1-555-01{rng.randint(0, 99):02d}"

    if kind in {"LOCATION", "GPE", "LOC"}:
        return rng.choice(pools.cities)

    if kind in {"ORGANIZATION", "ORG"}:
        return rng.choice(pools.companies)

    if kind in {"IP_ADDRESS", "IPV4"}:
        return f"192.0.2.{rng.randint(1, 254)}"

    if kind == "IPV6":
        return f"2001:db8::{_hex(rng, 4)}"

    if kind == "CREDIT_CARD":
        body = "4000" + "".join(str(rng.randint(0, 9)) for _ in range(11))
        number = body + _luhn_check_digit(body)
        if " " in original:
            return " ".join(number[i : i + 4] for i in range(0, 16, 4))
        return number

    if kind == "US_SSN":
        return f"666-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"

    if kind == "IBAN_CODE":
        return f"GB00LONO{rng.randint(10**9, 10**10 - 1)}"

    if kind in {"NRP", "NATIONALITY"}:
        return rng.choice(pools.nationalities)

    if kind in {"URL", "DOMAIN_NAME"}:
        word = rng.choice(pools.domain_words)
        domain = f"{word}.example.com"
        if "://" in original:
            return f"https://{domain}"
        return domain

    if kind in {"DATE_TIME", "DATE"}:
        return f"{rng.randint(2021, 2024)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"

    if kind == "CRYPTO":
        return f"bc1q{_hex(rng, 32)}"

    return f"LONO-{kind or 'ENTITY'}-{_hex(rng, 6)}"