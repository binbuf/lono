"""The Lono security pipeline: detect, decide, transform."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from lono_gateway.detectors import DetectorUnavailable
from lono_gateway.detectors.injection import InjectionDetector
from lono_gateway.detectors.pii import PiiDetector
from lono_gateway.detectors.secrets import SecretDetector
from lono_gateway.detectors.urls import UrlDetector
from lono_gateway.models import Detection, Finding, RequestContext, preview_span, resolve_overlaps
from lono_gateway.pipeline.shapes import REQUEST_WALKERS, RESPONSE_WALKERS
from lono_gateway.pipeline.types import ResponseOutcome, TextResult
from lono_gateway.pseudonymizer import Pseudonymizer, ResolvedDetection
from lono_gateway.rehydrator import Rehydrator, load_rehydrator
from lono_gateway.settings import SecurityConfig

logger = logging.getLogger(__name__)


@dataclass
class RequestOutcome:
    payload: Any
    findings: list[Finding] = field(default_factory=list)
    blocked: bool = False
    block_kinds: list[str] = field(default_factory=list)
    detector_error: str | None = None


ProcessText = Callable[..., Awaitable[TextResult]]


def _merge(payload: Any, results: list[TextResult]) -> RequestOutcome:
    findings: list[Finding] = []
    blocked = False
    kinds: list[str] = []
    for result in results:
        findings.extend(result.findings)
        blocked = blocked or result.blocked
        kinds.extend(result.block_kinds)
    return RequestOutcome(payload=payload, findings=findings, blocked=blocked, block_kinds=kinds)


class SecurityPipeline:
    def __init__(self, cfg: SecurityConfig, store) -> None:
        self.cfg = cfg
        self.store = store
        self.secrets = SecretDetector(cfg.detectors.secrets)
        self.pii = PiiDetector(cfg.detectors.pii, cfg.fail_closed)
        self.injection = InjectionDetector(cfg.detectors.injection)
        self.urls = UrlDetector(cfg.detectors.urls)

    async def aclose(self) -> None:
        await self.pii.aclose()

    # ------------------------------------------------------------------ input

    async def process_text(
        self,
        text: str,
        ctx: RequestContext,
        *,
        flag_only: bool = False,
        use_pii: bool = True,
        use_injection: bool = True,
        use_urls: bool = True,
    ) -> TextResult:
        if not text:
            return TextResult(text=text)
        try:
            detections = await self._collect(
                text, use_pii=use_pii, use_injection=use_injection, use_urls=use_urls
            )
        except DetectorUnavailable as exc:
            if self.cfg.fail_closed:
                return TextResult(text=text, blocked=True, block_kinds=["detector_unavailable"])
            logger.warning("detector unavailable, continuing fail-open: %s", exc)
            detections = []

        resolved: list[ResolvedDetection] = []
        for detection in detections:
            action = "observed" if ctx.mode == "observe" else self._action_for(detection, ctx)
            if flag_only and action not in {"observed"}:
                action = "flag"
            resolved.append(ResolvedDetection(detection=detection, action=action))

        self._promote_injection_aggregate(resolved, ctx)

        pseudonymizer = Pseudonymizer(self.store, self.cfg.pseudonymization, ctx.session_id)
        substituted = pseudonymizer.substitute(text, resolved)
        return TextResult(
            text=substituted.text,
            findings=substituted.findings,
            mappings=substituted.mappings,
            blocked=substituted.blocked,
            block_kinds=substituted.block_kinds,
        )

    async def _collect(
        self, text: str, *, use_pii: bool, use_injection: bool, use_urls: bool
    ) -> list[Detection]:
        detections = self.secrets.scan(text)
        if use_pii:
            detections.extend(await self.pii.scan(text))
        if use_urls:
            detections.extend(self.urls.scan(text))
        if use_injection:
            detections.extend(self.injection.scan(text))
        return resolve_overlaps(detections)

    def _action_for(self, detection: Detection, ctx: RequestContext) -> str:
        if detection.detector == "secrets":
            return self.cfg.detectors.secrets.action
        if detection.detector.startswith("pii"):
            return self.cfg.detectors.pii.actions.get(
                detection.kind, self.cfg.detectors.pii.default_action
            )
        if detection.detector == "injection":
            cfg = self.cfg.detectors.injection
            if ctx.mode == "enforce" and cfg.action == "block" and detection.score >= cfg.block_threshold:
                return "block"
            return "flag"
        if detection.detector == "urls":
            cfg = self.cfg.detectors.urls
            if ctx.mode == "enforce" and cfg.action == "block" and detection.score >= cfg.block_threshold:
                return "block"
            return "flag"
        return "flag"

    def _promote_injection_aggregate(
        self, resolved: list[ResolvedDetection], ctx: RequestContext
    ) -> None:
        if ctx.mode != "enforce":
            return
        cfg = self.cfg.detectors.injection
        if not cfg.enabled or cfg.action != "block":
            return
        injection_hits = [item.detection for item in resolved if item.detection.detector == "injection"]
        score = self.injection.aggregate_score(injection_hits)
        if score < cfg.block_threshold:
            return
        candidates = [item for item in resolved if item.detection.detector == "injection" and item.action != "block"]
        if candidates:
            candidates.sort(key=lambda item: item.detection.score, reverse=True)
            candidates[0].action = "block"

    # --------------------------------------------------------------- request

    async def process_request(self, shape: str, payload: Any, ctx: RequestContext) -> RequestOutcome:
        walker = REQUEST_WALKERS.get(shape)
        if walker is None or not isinstance(payload, dict):
            return RequestOutcome(payload=payload)

        async def process(text: str, **kwargs: Any) -> TextResult:
            return await self.process_text(text, ctx, **kwargs)

        results = await walker(payload, process, self.cfg.inspect_tools)
        return _merge(payload, results)

    # -------------------------------------------------------------- response

    async def process_response(self, shape: str, payload: Any, ctx: RequestContext) -> ResponseOutcome:
        walker = RESPONSE_WALKERS.get(shape)
        if walker is None or not isinstance(payload, dict):
            return ResponseOutcome(payload=payload)
        rehydrator = load_rehydrator(
            self.store, ctx.session_id, self.cfg.pseudonymization.stable_across_sessions
        )

        async def process(text: str) -> TextResult:
            return await self._process_output(text, ctx, rehydrator)

        results = await walker(payload, process)
        findings: list[Finding] = []
        for result in results:
            findings.extend(result.findings)
        return ResponseOutcome(payload=payload, findings=findings)

    async def _process_output(self, text: str, ctx: RequestContext, rehydrator: Rehydrator) -> TextResult:
        if not text:
            return TextResult(text=text)
        cfg = self.cfg.output_scan
        if not cfg.enabled or ctx.mode == "observe":
            if ctx.mode == "observe" and cfg.enabled:
                detections = await self._collect_output(text, cfg)
                resolved = [ResolvedDetection(det, "observed") for det in detections]
                substituted = Pseudonymizer(self.store, self.cfg.pseudonymization, ctx.session_id).substitute(
                    text, resolved
                )
                return TextResult(
                    text=rehydrator.rehydrate(text),
                    findings=substituted.findings,
                    blocked=False,
                )
            return TextResult(text=rehydrator.rehydrate(text))

        detections = await self._collect_output(text, cfg)
        resolved: list[ResolvedDetection] = []
        for detection in detections:
            if cfg.action == "mask" and detection.detector == "secrets":
                action = "mask"
            else:
                action = "flag"
            resolved.append(ResolvedDetection(detection=detection, action=action))
        substituted = Pseudonymizer(self.store, self.cfg.pseudonymization, ctx.session_id).substitute(
            text, resolved
        )
        return TextResult(text=rehydrator.rehydrate(substituted.text), findings=substituted.findings)

    async def _collect_output(self, text: str, cfg) -> list[Detection]:
        detections: list[Detection] = []
        if cfg.secrets:
            detections.extend(self.secrets.scan(text))
        if cfg.pii:
            detections.extend(await self.pii.scan(text))
        if cfg.injection:
            detections.extend(self.injection.scan(text))
        return resolve_overlaps(detections)

    async def scan_text_findings(
        self, text: str, ctx: RequestContext, *, use_pii: bool = False
    ) -> list[Finding]:
        """Record-only scan (used for post-stream audit); never transforms text."""
        if not text:
            return []
        detections = await self._collect(text, use_pii=use_pii, use_injection=True, use_urls=True)
        findings: list[Finding] = []
        for detection in detections:
            action = "observed" if ctx.mode == "observe" else "flag"
            findings.append(
                Finding(
                    detector=detection.detector,
                    kind=detection.kind,
                    start=detection.start,
                    end=detection.end,
                    score=detection.score,
                    action=action,  # type: ignore[arg-type]
                    preview=preview_span(text, detection.start, detection.end),
                )
            )
        return findings