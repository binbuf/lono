"""Coverage for the provider credential catalog (llm_firewall_synthetic_secrets.csv).

The fixtures are the format-faithful synthetic values from the corpus, assembled
from prefix + body at runtime so no credential-shaped literal is committed (GitHub
push protection flags the raw strings even though they are fake). Detection must
work from the value alone for shaped credentials, and from the env-var name for
values that have no distinctive shape.
"""

from __future__ import annotations

from random import Random

from lono_gateway.detectors.secrets import SecretDetector
from lono_gateway.models import resolve_overlaps
from lono_gateway.secretsynth import generate_fake_secret
from lono_gateway.settings import SecretsConfig


def _v(*parts: str) -> str:
    return "".join(parts)


def _detector() -> SecretDetector:
    return SecretDetector(SecretsConfig())


# Value-only shapes: no env-var name or assignment context is provided.
_VALUE_PARTS: dict[str, tuple[str, str]] = {
    "GITHUB_TOKEN": ("ghp_", "WL7s3EU9ibN2645qhx_3qxGO-sbq46VLz34y"),
    "GITHUB_PAT": (
        "github_pat_",
        "fVc1GFQ3__zbxurxlp4jhvGRDzuqM0Mtcm2sM_nhthIEp9HH1GqPr_j1klhdFPj2iSK9s2K2FAMtPuca0U",
    ),
    "GITLAB_PAT": ("glpat-", "yttagBz-Z5iTv2q9GkFo"),
    "GITLAB_RUNNER_TOKEN": ("glrt-", "zK5e_b32X0s3jXlncvka"),
    "GITLAB_TRIGGER_TOKEN": ("glptt-", "MxMYbDRwKDCtDwfNQf4c"),
    "GITLAB_FEED_TOKEN": ("glft-", "W_tSo4SmOe225-YrorBv"),
    "GITLAB_OAUTH_SECRET": ("gloas-", "pY5JK4TT92tIWxxHUUNv"),
    "SLACK_APP_TOKEN": ("xapp-", "829021729001-210026386189-AlqQCQjQGFFzjCGh2O7Nf1xM"),
    "SLACK_CONFIG_TOKEN": ("xoxe.xoxp-", "649627905516-856492044279-yXI0iVwWexoFGfXk4bh9unxR"),
    "SLACK_WEBHOOK_URL": (
        "https://hooks.slack.com/services/",
        "TGQVYX1QY/BEYPE2T3C/oijedLp4Aa0C724cqb0I7gWJ",
    ),
    "DISCORD_WEBHOOK_URL": (
        "https://discord.com/api/webhooks/",
        "144756000718955222/rSWeYr1Pddy60V619C3z_m2CIDsS7oJe_Olisw5v7ejsIWfpuAnsDZNPx6AAqOAfW8Z1",
    ),
    "XAI_API_KEY": ("xai-", "oAR_C9_F9upwOVZCEyBYWg63alYFHnKkCDRnNiW2O-bUvI5_"),
    "CEREBRAS_API_KEY": ("csk-", "hlzbIBNIM6vYprer2f4TIZL_rR_mgPE49wJ4x_Gz4Zw3Pszl"),
    "MODAL_TOKEN_SECRET": ("ak-", "pyLUa1J6C6JwV3WQ04BCY4ip5kBbZSHAoL3U5YEb"),
    "JINA_API_KEY": ("jina_", "meooaEfL83_9RKoIoKTp-TmzmiW1HP0AERAbnkf1n9McF4bq"),
    "VOYAGE_API_KEY": ("pa-", "V_83VX403Jth-swhslzxZcusIo3fp6pSDhKmp2At6S2gGsyf"),
    "AWS_BEARER_TOKEN_BEDROCK": (
        "ABSK",
        "BcW5xzsJSbXtz1-s3GP9e3C9AhPALyJobAWxszHg_HJU3AaAGDGrgUqVFL_diq4k",
    ),
    "GOOGLE_CLIENT_SECRET": ("GOCSPX-", "20xFpEX-R9t0M9XgcGG7zF8G1Lea"),
    "STRIPE_WEBHOOK_SECRET": ("whsec_", "LFFIksg1AFG29aDkXbsQjgCZ"),
    "SQUARE_APPLICATION_SECRET": ("sq0csp-", "wvmVwi2bqeAhmI1jmXWai3ZTonz7BvzxNukXwWgu9Ew"),
    "ADYEN_API_KEY": ("AQE", "E5yZ56n3X7OUWQtMAUhZm7g88Fy7wTGCNPz1oq51GUEhs9Q3oxvx3CsID5vlmbdT"),
    "TWILIO_ACCOUNT_SID": ("AC", "60f30e27921702d5ba09a429a10133e1"),
    "RESEND_API_KEY": ("re_", "BWB7QQmlJm0vg0PacE7ut23MbiJq90JKxCSm"),
    "DOCKERHUB_TOKEN": ("dckr_pat_", "yzsi0K5U4PecdsbtOr6NiBbxVukPk77gUWIx"),
    "FIGMA_TOKEN": ("figd_", "lTivdYAVeFcwMgvXp1mYIs6ZIUZklJuVR29WsuREeac"),
    "CLICKUP_API_TOKEN": ("pk_", "4EXRwlOMZmVuUy231JaG3mt8yp2ibndHdBYA"),
    "DROPBOX_ACCESS_TOKEN": (
        "sl.",
        "QYfHnw8NJ41UE99J1nf9Reh1CoHLgIH2fdLPUIkt7onFA28Eif4Yy4Mn7oSrRtY8",
    ),
    "INTERCOM_ACCESS_TOKEN": ("dG9r", "oBWU6jgEQKopy2u9OsqevwRuUOCZ0O4UebdkcTn24ywGVDy73RQhAsKl"),
    "SENTRY_AUTH_TOKEN": (
        "sntrys_",
        "4Mw1OKeU34eBq31MSOcYfnecGus4rjxbnZaotAAYcCgUAMfZ3TGdm7XCsu1n5R7j",
    ),
    "HONEYCOMB_API_KEY": ("hc_", "SBGZAvnnyusfQoebdJWfFlRwHiKnELiq"),
    "PAGERDUTY_API_TOKEN": ("u+", "dsDklJPAAGhaWKgj2LJN"),
    "NETLIFY_AUTH_TOKEN": ("nfp_", "Hx96knUnwLkE0QHYZvvKYDyubq2XuwvYVf7lh9LE"),
    "RENDER_API_KEY": ("rnd_", "enYerP13tyIMuJdQcySACHktzNl58Nwr"),
    "FLY_API_TOKEN": (
        "FlyV1 ",
        "aO09PyRyJYHRTMbLynK0OgbHsFRdkZ3oXe748UBtL0oA2J16CSNadE4mnbO3kNaTuqUrmnrB76mQbF54nJH6"
        "k1dNsa7i5oIeZYnpxxmpLyjC6nd4G1SeRPa9",
    ),
    "NEON_API_KEY": ("neon_", "dkICPFlGODGitLV4ioyKBiCLwylQAyWYZx42nBlTAE4tJs3L"),
    "COCKROACH_API_KEY": (
        "cckey_",
        "7TCQmwbuBtFzAFZiDAn6UNWR9XW6NAQ9t8yLxj4nSdoCyFYhAD6CIu9Cf1x2lKpN",
    ),
    "UPSTASH_REDIS_REST_TOKEN": (
        "AX",
        "Q15nqrtvbGI7iCicKVshYbADCnSGRODJqlRRtsLgAXuYmCsRlAuN8XbqX5rhyS1Z",
    ),
    "STYTCH_SECRET": ("secret-live-", "cyB4C33oNVQueyTeF3WYs6eJFpqJHrJ4hpKvC20cPIjuxk7E"),
    "POSTHOG_PERSONAL_API_KEY": ("phx_", "hvy9767NRfjI221l6nklMwiAUbLQnMxrukXQgZyXWWdMCdRt"),
    "PINECONE_API_KEY": ("pcsk_", "nDYbVl3UMsylTnsOHNRKft43QYQ1VBnnbcUnYH2W0rIYsUIH"),
    "WOOCOMMERCE_CONSUMER_KEY": ("ck_", "oZf621yV186aKzWKRnm2urzKFu3EsHGRPJsq78SR"),
    "WOOCOMMERCE_CONSUMER_SECRET": ("cs_", "URq7ZALHu0TH9Y4PmxBVjYF6kw9yi0UTcId5OItF"),
    "VAULT_TOKEN": ("hvs.", "ZHb3jNCCKeBBLEoiXRlTEuh12wIAR3MdqOh61uQ7ifH2jLT5"),
    "PULUMI_ACCESS_TOKEN": ("pul-", "J1bSxDPpthPmSCFCVUfVAtZb7ahsTPwqdYTLaPpo"),
    "MAPBOX_ACCESS_TOKEN": (
        "pk.",
        "CYRv27LDZHUqXT565TRo2quVhxPeM9OKPF0TWICSsHmbms12Q0I2h8NL8SFbb9P2RWCvusg2PvzjEHpG",
    ),
    "MAPBOX_SECRET_TOKEN": (
        "sk.",
        "qrxNMR50Bq94ZBp5sjG4nVQd25EDvuHQWOHnK1kuWeGfdZiVigmKNpLVDU9GKdiaoS3CDXPG0X22vgdN",
    ),
    "GITGUARDIAN_API_KEY": ("ggshield_", "RUqHU7K1DvoCNBsOVA4m1reQy2pgmBycqRQfOLk7"),
    "SONAR_TOKEN": ("squ_", "6T7MTRt9wPR1FLq2GyWtJJ0h6jNQJfUSKKwL81E6"),
}

_VALUE_FIXTURES = {kind: _v(*parts) for kind, parts in _VALUE_PARTS.items()}


def test_catalog_value_shapes_detected_without_context() -> None:
    detector = _detector()
    for expected_kind, value in _VALUE_FIXTURES.items():
        kinds = {detection.kind for detection in detector.scan(value)}
        assert expected_kind in kinds, f"{expected_kind} not detected in {value!r} (got {kinds})"


# Values with no distinctive shape: only the env-var name identifies them.
_ENV_PARTS: dict[str, tuple[str, str]] = {
    "DD_API_KEY": ("vgiL29sVfhbjObo5", "ZpR6y2hAMFMm7ubh"),
    "CIRCLECI_TOKEN": ("5a93ed6a5c0c5b11f", "b079f94116dc8fa269f5e9b"),
    "AZURE_OPENAI_API_KEY": ("c17ff726585c8342", "8bfadbaf08349041"),
    "POSTMARK_SERVER_TOKEN": ("3e643bf6-f06f-5b2c-", "08ba-9010f849ac61"),
    "MAILGUN_SIGNING_KEY": ("3f713f01fdf1ebad699992c9", "fc51e858e955b5faf93cbb1b18a0e41d43475cf1"),
    "ATLASSIAN_API_TOKEN": ("BqEi3LnamJ", "RdhJLiFUzRy4mV"),
    "TRAVIS_TOKEN": ("cNfza6GbU", "wjU9con7NcX7E"),
    "MONGODB_ATLAS_PRIVATE_KEY": ("DiPqjHHg3N7lpBI", "M0wZd2LMS1a4wuyuLFdGq"),
    "SAMBANOVA_API_KEY": ("MyIB6yl1m8wP4CoYVnr5", "y4sST4zvPnHUmBHXFFly9_bZeJID"),
    "CLOUDFLARE_GLOBAL_API_KEY": ("Pfh8rjZvV8wCv0zkWmSNIz", "TSrwisbmyrP0B3m"),
    "TOGETHER_API_KEY": ("AIt7aFU5oXS5kBwoRAn55prXsNWf", "ZPPo2CoAHvDQmww8P8EXoevED4t9Jvs1RqKs"),
    "SNYK_TOKEN": ("eDIZ8r3gVqPcJWuwDv", "b8pBUSGU85dwcXNuOf"),
    "ALIAS_CLIENT_SECRET": ("gt_IpyoiZtr89A8U3uPk", "1rgM1O2DISqGejNqVOQPwCYdPO-l"),
}

_ENV_FIXTURES = {name: _v(*parts) for name, parts in _ENV_PARTS.items()}


def test_catalog_env_assignment_detects_generic_values() -> None:
    detector = _detector()
    for name, value in _ENV_FIXTURES.items():
        assignments = (
            f"{name}={value}",
            f'"{name}": "{value}"',
            f'$env:{name} = "{value}"',
        )
        for text in assignments:
            detections = detector.scan(text)
            assert any(
                detection.kind == name and detection.value == value for detection in detections
            ), f"{name} ({value!r}) not detected in {text!r}"


def test_catalog_assignment_masks_value_not_name() -> None:
    text = f'DD_API_KEY="{_ENV_FIXTURES["DD_API_KEY"]}"'
    resolved = resolve_overlaps(_detector().scan(text))
    assert [detection.value for detection in resolved] == [_ENV_FIXTURES["DD_API_KEY"]]


def test_catalog_ignores_placeholder_and_reference_values() -> None:
    detector = _detector()
    benign = (
        "OPENAI_API_KEY=${OPENAI_API_KEY}",
        "OPENAI_API_KEY=sk-your-key-here",
        "SECRET_KEY=my-secret-name",
        "API_TOKEN=1234",
        "GOOGLE_APPLICATION_CREDENTIALS=/path/key.json",
        "PUBLIC_KEY=ssh-rsa-AAAA",
        "STRIPE_PUBLISHABLE_KEY=pk_live_public",  # too short to be a key body
    )
    for text in benign:
        kinds = {detection.kind for detection in detector.scan(text)}
        assert not (kinds & set(_ENV_FIXTURES)), (text, kinds)


def test_catalog_ignores_public_and_publishable_names() -> None:
    detector = _detector()
    text = "MONGODB_ATLAS_PUBLIC_KEY=4mOgJcni6QWlnixj"
    assert not any(detection.kind == "MONGODB_ATLAS_PUBLIC_KEY" for detection in detector.scan(text))


# The prefix each fake must preserve.
def test_catalog_fake_preserves_new_prefixes() -> None:
    for kind, value in _VALUE_FIXTURES.items():
        fake = generate_fake_secret(kind, value, Random(7))
        assert fake != value
        assert len(fake) == len(value), (kind, fake, value)
        for prefix in _EXPECTED_PREFIXES.get(kind, ()):
            assert fake.startswith(prefix), (kind, fake)


_EXPECTED_PREFIXES: dict[str, tuple[str, ...]] = {
    "GITLAB_RUNNER_TOKEN": ("glrt-",),
    "SLACK_CONFIG_TOKEN": ("xoxe.",),
    "XAI_API_KEY": ("xai-",),
    "CEREBRAS_API_KEY": ("csk-",),
    "MODAL_TOKEN_SECRET": ("ak-",),
    "GOOGLE_CLIENT_SECRET": ("GOCSPX-",),
    "STRIPE_WEBHOOK_SECRET": ("whsec_",),
    "SQUARE_APPLICATION_SECRET": ("sq0csp-",),
    "ADYEN_API_KEY": ("AQE",),
    "DOCKERHUB_TOKEN": ("dckr_pat_",),
    "FIGMA_TOKEN": ("figd_",),
    "DROPBOX_ACCESS_TOKEN": ("sl.",),
    "SENTRY_AUTH_TOKEN": ("sntrys_",),
    "NETLIFY_AUTH_TOKEN": ("nfp_",),
    "RENDER_API_KEY": ("rnd_",),
    "VAULT_TOKEN": ("hvs.",),
    "PULUMI_ACCESS_TOKEN": ("pul-",),
    "MAPBOX_ACCESS_TOKEN": ("pk.",),
    "MAPBOX_SECRET_TOKEN": ("sk.",),
    "GITGUARDIAN_API_KEY": ("ggshield_",),
    "SONAR_TOKEN": ("squ_",),
}