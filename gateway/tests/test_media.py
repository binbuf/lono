from __future__ import annotations

import base64

from lono_gateway.audit.media import MediaStore, externalize_media
from lono_gateway.audit.store import AuditStore
from lono_gateway.settings import MediaConfig

PNG_BYTES = b"\x89PNG\r\n\x1a\nfake-image-bytes"


def _store(tmp_path) -> tuple[AuditStore, MediaStore]:
    store = AuditStore(str(tmp_path / "audit.db"))
    media = MediaStore(MediaConfig(backend="local", local_path=str(tmp_path / "media")), store)
    return store, media


async def test_externalize_openai_image_is_content_addressed(tmp_path) -> None:
    store, media = _store(tmp_path)
    await media.ensure_ready()
    data_url = "data:image/png;base64," + base64.b64encode(PNG_BYTES).decode()
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "look at this"},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            }
        ]
    }
    audit, refs = await externalize_media(payload, media, "r1")

    # The outgoing payload is untouched; the audit copy references the CAS object.
    assert payload["messages"][0]["content"][1]["image_url"]["url"] == data_url
    assert len(refs) == 1
    ref = refs[0]
    assert audit["messages"][0]["content"][1]["image_url"]["url"] == f"lono-media://sha256/{ref['sha256']}"
    assert media.read_sync(ref) == PNG_BYTES
    assert store.get_media(ref["sha256"]) is not None

    # Identical bytes are stored once.
    _, refs_again = await externalize_media(payload, media, "r2")
    assert refs_again[0]["sha256"] == ref["sha256"]
    store.close()


async def test_externalize_anthropic_image(tmp_path) -> None:
    store, media = _store(tmp_path)
    await media.ensure_ready()
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/jpeg",
                            "data": base64.b64encode(PNG_BYTES).decode(),
                        },
                    }
                ],
            }
        ]
    }
    audit, refs = await externalize_media(payload, media, "r1")
    assert len(refs) == 1
    source = audit["messages"][0]["content"][0]["source"]
    assert source["data"] == ""
    assert source["lono_media"]["sha256"] == refs[0]["sha256"]
    store.close()


async def test_externalize_remote_url_records_without_fetch(tmp_path) -> None:
    store, media = _store(tmp_path)
    await media.ensure_ready()
    payload = {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}}]}]}
    audit, refs = await externalize_media(payload, media, "r1")
    assert len(refs) == 1
    assert refs[0]["remote"] is True
    assert audit["messages"][0]["content"][0]["image_url"]["url"] == "https://example.com/cat.png"
    store.close()