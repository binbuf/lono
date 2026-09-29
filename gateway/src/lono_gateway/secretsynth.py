"""Format-preserving synthetic secrets.

Secrets are never sent to a provider verbatim. Historically the gateway
replaced them with ``[REDACTED:...]`` markers, which told the provider exactly
what happened. Lono instead substitutes a *plausible but fake* value that keeps
the shape of the original (prefix, length, character classes) so the provider
cannot tell a request was redacted and downstream tooling keeps working.

The synthetic value is deterministic for a given seed (session/key) so the same
secret maps to the same fake within a conversation. Because each fake is unique
to its original, the pseudonymizer records a reversible mapping for masked
secrets: the provider only ever sees the fake, but the gateway restores the real
credential in the response the client receives.
"""

from __future__ import annotations

import random
import re
import string
from collections import deque

_HASHY_RE = re.compile(
    r"^(?:[0-9a-fA-F]{32,}|"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)

_ASCII_LOWER = string.ascii_lowercase
_ASCII_UPPER = string.ascii_uppercase
_ASCII_DIGITS = string.digits
_B64 = _ASCII_UPPER + _ASCII_LOWER + _ASCII_DIGITS + "-_"
_HEX = "0123456789abcdef"

# Recognizable prefixes per secret family. The prefix is kept so the fake looks
# like the real thing to a provider; only the body is randomized.
_KNOWN_PREFIXES: dict[str, tuple[str, ...]] = {
    "OPENAI_API_KEY": ("sk-proj-", "sk-"),
    "ANTHROPIC_API_KEY": ("sk-ant-",),
    "GITHUB_TOKEN": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "GITHUB_PAT": ("github_pat_",),
    "GITLAB_PAT": ("glpat-",),
    "SLACK_TOKEN": ("xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"),
    "STRIPE_KEY": ("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
    "GOOGLE_API_KEY": ("AIza",),
    "AWS_ACCESS_KEY_ID": ("AKIA", "ASIA"),
    "NPM_TOKEN": ("npm_",),
    "PYPI_TOKEN": ("pypi-",),
    "DIGITALOCEAN_TOKEN": ("dop_v1_",),
    "DIGITALOCEAN_OAUTH_TOKEN": ("doo_v1_",),
    "DIGITALOCEAN_REFRESH_TOKEN": ("dor_v1_",),
    "SHOPIFY_TOKEN": ("shpat_",),
    "SHOPIFY_CUSTOM_APP_TOKEN": ("shpca_",),
    "SHOPIFY_PRIVATE_APP_TOKEN": ("shppa_",),
    "SHOPIFY_SHARED_SECRET": ("shpss_",),
    "TWILIO_API_KEY": ("SK",),
    "SENDGRID_KEY": ("SG.",),
    "MAILGUN_KEY": ("key-",),
    "HEROKU_API_KEY": ("",),
    "BEARER_TOKEN": ("",),
    "RUNPOD_API_KEY": ("rpa_",),
    "RUNPOD_MANAGEMENT_KEY": ("mom_",),
    "HUGGINGFACE_TOKEN": ("hf_",),
    "GROQ_API_KEY": ("gsk_",),
    "PERPLEXITY_API_KEY": ("pplx-",),
    "OPENROUTER_API_KEY": ("sk-or-v1-",),
    "REPLICATE_API_TOKEN": ("r8_",),
    "FIREWORKS_API_KEY": ("fw_",),
    "TOGETHER_API_KEY": ("tgp_v1_",),
    "POSTMAN_API_KEY": ("PMAK-",),
    "NOTION_API_KEY": ("ntn_",),
    "NOTION_INTEGRATION_TOKEN": ("secret_",),
    "LINEAR_API_KEY": ("lin_api_",),
    "NEW_RELIC_USER_KEY": ("NRAK-",),
    "PLANETSCALE_TOKEN": ("pscale_tkn_",),
    "SUPABASE_ACCESS_TOKEN": ("sbp_",),
    "DOPPLER_TOKEN": ("dp.pt.",),
    "GRAFANA_API_KEY": ("glc_",),
    "GRAFANA_SERVICE_ACCOUNT_TOKEN": ("glsa_",),
    "DATABRICKS_TOKEN": ("dapi",),
    "EASYPOST_API_KEY": ("EZAK",),
    "EASYPOST_TEST_API_KEY": ("EZTK",),
    "CLICKHOUSE_CLOUD_KEY": ("4b1d",),
    "FLY_IO_TOKEN": ("fo1_",),
    "SQUARE_ACCESS_TOKEN": ("EAAA",),
    "SQUARE_SECRET": ("sq0atp-",),
    "GOOGLE_OAUTH_TOKEN": ("ya29.",),
    "ALIBABA_ACCESS_KEY_ID": ("LTAI",),
    "ADOBE_CLIENT_SECRET": ("p8e-",),
    "AIRTABLE_PAT": ("pat",),
    "ELEVENLABS_API_KEY": ("sk_",),
    # Catalogued from llm_firewall_synthetic_secrets.csv.
    "GITLAB_RUNNER_TOKEN": ("glrt-",),
    "GITLAB_TRIGGER_TOKEN": ("glptt-",),
    "GITLAB_FEED_TOKEN": ("glft-",),
    "GITLAB_OAUTH_SECRET": ("gloas-",),
    "SLACK_APP_TOKEN": ("xapp-",),
    "SLACK_CONFIG_TOKEN": ("xoxe.",),
    "SLACK_LEGACY_TOKEN": ("xoxc-", "xoxd-"),
    "SLACK_WEBHOOK_URL": ("https://hooks.slack.com/services/",),
    "DISCORD_WEBHOOK_URL": ("https://discord.com/api/webhooks/",),
    "XAI_API_KEY": ("xai-",),
    "CEREBRAS_API_KEY": ("csk-",),
    "MODAL_TOKEN_SECRET": ("ak-",),
    "JINA_API_KEY": ("jina_",),
    "VOYAGE_API_KEY": ("pa-",),
    "AWS_BEARER_TOKEN_BEDROCK": ("ABSK",),
    "GOOGLE_CLIENT_SECRET": ("GOCSPX-",),
    "STRIPE_WEBHOOK_SECRET": ("whsec_",),
    "SQUARE_APPLICATION_SECRET": ("sq0csp-",),
    "ADYEN_API_KEY": ("AQE",),
    "TWILIO_ACCOUNT_SID": ("AC",),
    "RESEND_API_KEY": ("re_",),
    "DOCKERHUB_TOKEN": ("dckr_pat_",),
    "FIGMA_TOKEN": ("figd_",),
    "CLICKUP_API_TOKEN": ("pk_",),
    "DROPBOX_ACCESS_TOKEN": ("sl.",),
    "INTERCOM_ACCESS_TOKEN": ("dG9r",),
    "SENTRY_AUTH_TOKEN": ("sntrys_",),
    "HONEYCOMB_API_KEY": ("hc_",),
    "PAGERDUTY_API_TOKEN": ("u+",),
    "NETLIFY_AUTH_TOKEN": ("nfp_",),
    "RENDER_API_KEY": ("rnd_",),
    "FLY_API_TOKEN": ("FlyV1 ",),
    "NEON_API_KEY": ("neon_",),
    "COCKROACH_API_KEY": ("cckey_",),
    "UPSTASH_REDIS_REST_TOKEN": ("AX",),
    "STYTCH_SECRET": ("secret-live-",),
    "CLERK_PUBLISHABLE_KEY": ("pk_live_", "pk_test_"),
    "LAUNCHDARKLY_SDK_KEY": ("sdk-",),
    "LAUNCHDARKLY_API_TOKEN": ("api-",),
    "POSTHOG_PERSONAL_API_KEY": ("phx_",),
    "PINECONE_API_KEY": ("pcsk_",),
    "WOOCOMMERCE_CONSUMER_KEY": ("ck_",),
    "WOOCOMMERCE_CONSUMER_SECRET": ("cs_",),
    "VAULT_TOKEN": ("hvs.",),
    "PULUMI_ACCESS_TOKEN": ("pul-",),
    "MAPBOX_ACCESS_TOKEN": ("pk.",),
    "MAPBOX_SECRET_TOKEN": ("sk.",),
    "GITGUARDIAN_API_KEY": ("ggshield_",),
    "SONAR_TOKEN": ("squ_",),
}


def _class_char(char: str, rng: random.Random) -> str:
    if char.islower():
        return rng.choice(_ASCII_LOWER)
    if char.isupper():
        return rng.choice(_ASCII_UPPER)
    if char.isdigit():
        return rng.choice(_ASCII_DIGITS)
    return char


def format_preserving(value: str, rng: random.Random) -> str:
    """Randomize a value while preserving punctuation and character classes."""
    return "".join(_class_char(char, rng) for char in value)


def _random_body(length: int, alphabet: str, rng: random.Random) -> str:
    return "".join(rng.choice(alphabet) for _ in range(max(1, length)))


def _jwt(rng: random.Random, original: str) -> str:
    parts = original.split(".")
    lengths = [len(part) for part in parts] or [36, 24, 43]
    if len(lengths) != 3:
        lengths = [36, 24, 43]
    return ".".join(_random_body(length, _B64, rng) for length in lengths)


def generate_fake_secret(kind: str, original: str, rng: random.Random) -> str:
    """Produce a deterministic, format-preserving fake for a secret span."""
    kind = (kind or "").upper()

    if _HASHY_RE.match(original) or kind in {"AWS_SECRET_ACCESS_KEY", "AZURE_STORAGE_KEY"}:
        return _random_body(len(original), _B64, rng)

    for prefix in _KNOWN_PREFIXES.get(kind, ()):
        if prefix and original.startswith(prefix):
            return prefix + format_preserving(original[len(prefix) :], rng)

    if kind in {"JWT", "SAS_TOKEN"}:
        return _jwt(rng, original)

    if kind in {"PRIVATE_KEY", "CONNECTION_STRING", "BASIC_AUTH"}:
        return format_preserving(original, rng)

    if kind == "HIGH_ENTROPY_STRING" or not kind:
        return format_preserving(original, rng)

    # Unknown family: keep the shape, including any recognizable prefix run.
    return format_preserving(original, rng)


# --------------------------------------------------------------------------
# Registry of values Lono itself synthesized, so the detector does not flag a
# fake as if it were a fresh secret when it reappears in later turns.

_MAX_REMEMBERED = 4096
_synthesized: set[str] = set()
_synthesized_order: deque[str] = deque()


def remember_synthetic(value: str) -> None:
    if not value or len(value) < 8 or value in _synthesized:
        return
    _synthesized.add(value)
    _synthesized_order.append(value)
    while len(_synthesized_order) > _MAX_REMEMBERED:
        _synthesized.discard(_synthesized_order.popleft())


def is_synthetic(value: str) -> bool:
    return value in _synthesized