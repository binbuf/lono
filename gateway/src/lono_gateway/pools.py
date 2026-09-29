"""Deterministic synthetic value pools used for pseudonymization.

The shipped defaults live in ``config/lists/*.txt``; these Python lists are the
ultimate fallback when no list file is configured or readable. Individual
categories can be overridden inline via ``pseudonymization.pools``.
"""

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

STREET_NAMES = [
    "Maple", "Oak", "Cedar", "Birch", "Pine", "Elm", "Walnut", "Chestnut", "Juniper", "Aspen",
    "Lakeview", "Riverside", "Hillcrest", "Sunset", "Highland", "Meadow", "Prairie", "Canyon",
    "Harbor", "Bayside", "Foxglove", "Bluebell", "Willow", "Sycamore", "Magnolia",
]

STREET_SUFFIXES = [
    "Street", "Avenue", "Road", "Boulevard", "Lane", "Drive", "Court", "Way", "Place",
    "Terrace", "Circle", "Trail", "Parkway",
]

DEFAULT_LISTS: dict[str, list[str]] = {
    "first_names": FIRST_NAMES,
    "last_names": LAST_NAMES,
    "cities": CITIES,
    "companies": COMPANIES,
    "domain_words": DOMAIN_WORDS,
    "street_names": STREET_NAMES,
    "street_suffixes": STREET_SUFFIXES,
}


@dataclass
class Pools:
    values: dict[str, list[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        merged: dict[str, list[str]] = {name: list(items) for name, items in DEFAULT_LISTS.items()}
        for name, items in (self.values or {}).items():
            cleaned = [str(item).strip() for item in items if str(item).strip()]
            if cleaned:
                # Unknown names are kept: they act as literal pools for that category.
                merged[name] = cleaned
        # Never allow an empty built-in pool.
        for name, items in list(merged.items()):
            if not items and name in DEFAULT_LISTS:
                merged[name] = list(DEFAULT_LISTS[name])
        self.values = merged

    def get(self, name: str) -> list[str]:
        return self.values.get(name) or list(DEFAULT_LISTS.get(name, ["value"]))

    def custom_pool(self, kind: str) -> list[str] | None:
        """A user-supplied literal pool for an exact entity category, if any."""
        return self.values.get((kind or "").upper())

    @classmethod
    def from_config(
        cls, inline: dict[str, list[str]] | None = None, lists: dict[str, list[str]] | None = None
    ) -> Pools:
        merged: dict[str, list[str]] = dict(lists or {})
        merged.update(inline or {})
        return cls(merged)


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


_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def generate_pseudonym(kind: str, original: str, rng: random.Random, pools: Pools) -> str:
    """Generate a deterministic synthetic replacement for an entity span."""
    kind = (kind or "").upper()

    # A user-supplied literal pool for this exact category wins over generated values.
    custom = pools.custom_pool(kind)
    if custom:
        return rng.choice(custom)

    if kind in {"EMAIL_ADDRESS", "EMAIL"}:
        first = rng.choice(pools.get("first_names")).lower()
        last = rng.choice(pools.get("last_names")).lower()
        suffix = f"{rng.randint(1, 99)}" if rng.random() < 0.4 else ""
        return f"{first}.{last}{suffix}@example.com"

    if kind in {"PERSON", "PER"}:
        first = rng.choice(pools.get("first_names"))
        if " " in original.strip():
            return f"{first} {rng.choice(pools.get('last_names'))}"
        return first

    if kind in {"PHONE_NUMBER", "PHONE"}:
        return f"+1-555-01{rng.randint(0, 99):02d}"

    if kind in {"LOCATION", "GPE", "LOC"}:
        return rng.choice(pools.get("cities"))

    if kind in {"ORGANIZATION", "ORG", "COMPANY"}:
        return rng.choice(pools.get("companies"))

    if kind in {"STREET_ADDRESS", "ADDRESS"}:
        number = rng.randint(1, 9999)
        street = rng.choice(pools.get("street_names"))
        suffix = rng.choice(pools.get("street_suffixes"))
        unit = f" Apt {rng.randint(1, 90)}" if rng.random() < 0.25 else ""
        return f"{number} {street} {suffix}{unit}"

    if kind in {"POSTAL_CODE", "ZIP_CODE", "ZIP"}:
        if any(char.isalpha() for char in original):
            return (
                f"{rng.choice(_ALPHA)}{rng.choice(_ALPHA)}{rng.randint(1, 9)} "
                f"{rng.randint(1, 9)}{rng.choice(_ALPHA)}{rng.choice(_ALPHA)}"
            )
        base = f"{rng.randint(10000, 99999)}"
        return f"{base}-{rng.randint(1000, 9999)}" if "-" in original else base

    if kind in {"IP_ADDRESS", "IPV4"}:
        return f"192.0.2.{rng.randint(1, 254)}"

    if kind == "IPV6":
        return f"2001:db8::{_hex(rng, 4)}"

    if kind == "MAC_ADDRESS":
        return ":".join(_hex(rng, 2) for _ in range(6))

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

    if kind in {"URL", "DOMAIN_NAME"}:
        word = rng.choice(pools.get("domain_words"))
        domain = f"{word}.example.com"
        if "://" in original:
            return f"https://{domain}"
        return domain

    if kind in {"BTC_ADDRESS", "CRYPTO_BTC"}:
        return f"bc1q{_hex(rng, 38)}"

    if kind in {"ETH_ADDRESS", "CRYPTO_ETH"}:
        return f"0x{_hex(rng, 40)}"

    if kind == "CRYPTO":
        return f"bc1q{_hex(rng, 38)}"

    if kind in {"PROJECT", "PROJECT_CODENAME", "PROJECT_NAME"}:
        return f"Project {rng.choice(pools.get('domain_words')).capitalize()}"

    if kind in {"DATE_TIME", "DATE"}:
        return f"{rng.randint(2021, 2024)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"

    return f"LONO-{kind or 'ENTITY'}-{_hex(rng, 6)}"