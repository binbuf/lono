"""Provider credential shapes catalogued from ``llm_firewall_synthetic_secrets.csv``.

Each entry is ``(kind, pattern, score)`` where ``pattern`` matches the credential
*value on its own*. Nothing here requires the env-var name or a surrounding
``KEY=`` assignment: a bare token pasted into a prompt, echoed in tool output or
embedded in a URL is still caught.

The CSV also contains many credentials whose values have no distinctive shape at
all (for example the ``*_API_KEY`` / ``*_CLIENT_SECRET`` alias rows, which are all
"48-char high entropy"). Those are covered by the env-var name markers in
``detectors.secrets`` rather than by a value pattern.
"""

from __future__ import annotations

# (kind, regex source, score). Compiled by ``detectors.secrets``.
VALUE_PATTERNS: list[tuple[str, str, float]] = [
    # ---------------------------------------------------------- source control
    ("GITLAB_RUNNER_TOKEN", r"\bglrt-[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("GITLAB_TRIGGER_TOKEN", r"\bglptt-[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("GITLAB_FEED_TOKEN", r"\bglft-[A-Za-z0-9_\-]{20,}\b", 0.9),
    ("GITLAB_OAUTH_SECRET", r"\bgloas-[A-Za-z0-9_\-]{20,}\b", 0.95),
    # --------------------------------------------------------------- messaging
    ("SLACK_APP_TOKEN", r"\bxapp-[A-Za-z0-9\-]{10,}\b", 0.95),
    ("SLACK_CONFIG_TOKEN", r"\bxoxe[.\-](?:xox[bp]|xapp)-[A-Za-z0-9\-]{10,}\b", 0.95),
    ("SLACK_LEGACY_TOKEN", r"\bxox[cd]-[A-Za-z0-9\-]{10,}\b", 0.9),
    (
        "SLACK_WEBHOOK_URL",
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
        0.95,
    ),
    (
        "DISCORD_WEBHOOK_URL",
        r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
        0.95,
    ),
    # ------------------------------------------------------------------- AI/ML
    ("XAI_API_KEY", r"\bxai-[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("CEREBRAS_API_KEY", r"\bcsk-[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("MODAL_TOKEN_SECRET", r"\bak-[A-Za-z0-9]{20,}\b", 0.9),
    ("JINA_API_KEY", r"\bjina_[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("VOYAGE_API_KEY", r"\bpa-[A-Za-z0-9_\-]{20,}\b", 0.9),
    ("AWS_BEARER_TOKEN_BEDROCK", r"\bABSK[A-Za-z0-9_\-]{40,}\b", 0.9),
    ("GOOGLE_CLIENT_SECRET", r"\bGOCSPX-[A-Za-z0-9_\-]{20,}\b", 0.95),
    # --------------------------------------------------------------- payments
    ("STRIPE_WEBHOOK_SECRET", r"\bwhsec_[A-Za-z0-9]{20,}\b", 0.95),
    ("SQUARE_APPLICATION_SECRET", r"\bsq0csp-[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("ADYEN_API_KEY", r"\bAQE[A-Za-z0-9+/=]{60,}\b", 0.85),
    # --------------------------------------------------------- communications
    ("TWILIO_ACCOUNT_SID", r"\bAC[0-9a-fA-F]{32}\b", 0.9),
    ("RESEND_API_KEY", r"\bre_[A-Za-z0-9_\-]{20,}\b", 0.85),
    # ------------------------------------------------------------ package/CI-CD
    ("DOCKERHUB_TOKEN", r"\bdckr_pat_[A-Za-z0-9_\-]{20,}\b", 0.95),
    # ----------------------------------------------------- SaaS / productivity
    ("FIGMA_TOKEN", r"\bfigd_[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("CLICKUP_API_TOKEN", r"\bpk_[A-Za-z0-9]{20,}\b", 0.85),
    ("DROPBOX_ACCESS_TOKEN", r"\bsl\.[A-Za-z0-9_\-]{40,}\b", 0.9),
    ("INTERCOM_ACCESS_TOKEN", r"\bdG9r[A-Za-z0-9+/=]{20,}\b", 0.9),
    # ----------------------------------------------------------- observability
    ("SENTRY_AUTH_TOKEN", r"\bsntrys_[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("HONEYCOMB_API_KEY", r"\bhc_[A-Za-z0-9]{20,}\b", 0.85),
    ("PAGERDUTY_API_TOKEN", r"\bu\+[A-Za-z0-9]{20,}\b", 0.85),
    # ----------------------------------------------------------- hosting / CDN
    ("NETLIFY_AUTH_TOKEN", r"\bnfp_[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("RENDER_API_KEY", r"\brnd_[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("FLY_API_TOKEN", r"\bFlyV1 [A-Za-z0-9_\-]{40,}\b", 0.9),
    # ---------------------------------------------------------- database / BaaS
    ("NEON_API_KEY", r"\bneon_[A-Za-z0-9_\-]{20,}\b", 0.9),
    ("COCKROACH_API_KEY", r"\bcckey_[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("UPSTASH_REDIS_REST_TOKEN", r"\bAX[A-Za-z0-9_\-]{30,}\b", 0.85),
    # ------------------------------------------------------------ identity/auth
    ("STYTCH_SECRET", r"\bsecret-live-[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("CLERK_PUBLISHABLE_KEY", r"\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b", 0.9),
    # --------------------------------------------------- analytics/feature flag
    ("LAUNCHDARKLY_SDK_KEY", r"\bsdk-[A-Za-z0-9_\-]{20,}\b", 0.9),
    ("LAUNCHDARKLY_API_TOKEN", r"\bapi-[A-Za-z0-9_\-]{20,}\b", 0.85),
    ("POSTHOG_PERSONAL_API_KEY", r"\bphx_[A-Za-z0-9_\-]{20,}\b", 0.95),
    # ------------------------------------------------- search / vector / data
    ("PINECONE_API_KEY", r"\bpcsk_[A-Za-z0-9_\-]{20,}\b", 0.95),
    # ---------------------------------------------------------------- commerce
    ("WOOCOMMERCE_CONSUMER_KEY", r"\bck_[A-Za-z0-9]{40,}\b", 0.9),
    ("WOOCOMMERCE_CONSUMER_SECRET", r"\bcs_[A-Za-z0-9]{40,}\b", 0.9),
    # ------------------------------------------------------------- cloud / infra
    ("VAULT_TOKEN", r"\bhvs\.[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("PULUMI_ACCESS_TOKEN", r"\bpul-[A-Za-z0-9_\-]{20,}\b", 0.9),
    # ----------------------------------------------------------------- misc API
    ("MAPBOX_ACCESS_TOKEN", r"\bpk\.[A-Za-z0-9_\-]{40,}\b", 0.9),
    ("MAPBOX_SECRET_TOKEN", r"\bsk\.[A-Za-z0-9_\-]{40,}\b", 0.9),
    ("GITGUARDIAN_API_KEY", r"\bggshield_[A-Za-z0-9_\-]{20,}\b", 0.95),
    ("SONAR_TOKEN", r"\bsqu_[A-Za-z0-9]{20,}\b", 0.9),
]

# Env-var name markers. When a variable whose name ends in one of these markers
# (as a whole name or an ``_``-delimited segment) is assigned a value, the value
# is a credential even if its shape is unremarkable. This is what covers the CSV
# alias/generic rows such as ``DD_API_KEY=<32 hex>`` and
# ``CIRCLECI_TOKEN=<40 hex>`` that the entropy heuristic deliberately skips
# because they look like hashes.
ENV_NAME_MARKERS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "secrets",
    "secret_key",
    "secret_access_key",
    "client_secret",
    "signing_secret",
    "webhook_secret",
    "app_secret",
    "application_secret",
    "api_key",
    "apikey",
    "api_token",
    "key",
    "token",
    "pat",
    "access_key",
    "access_key_id",
    "access_token",
    "auth_key",
    "auth_token",
    "oauth_token",
    "oauth_client_secret",
    "private_key",
    "private_token",
    "signing_key",
    "encryption_key",
    "session_key",
    "session_token",
    "master_key",
    "root_token",
    "license_key",
    "admin_key",
    "management_key",
    "service_key",
    "service_token",
    "service_account_key",
    "app_key",
    "sdk_key",
    "hmac_key",
    "hec_token",
    "write_key",
    "personal_access_token",
    "client_key",
    "account_key",
    "credential",
    "credentials",
)