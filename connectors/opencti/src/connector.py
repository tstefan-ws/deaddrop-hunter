"""OpenCTI external-import connector for the deaddrop-hunter STIX 2.1 feed.

Downloads the published bundle (``feeds/stix/deaddrop-hunter.bundle.json``) on a
schedule and pushes it into OpenCTI with ``helper.send_stix2_bundle``.

The fetch / validate / transform logic is plain functions so it can be unit-tested
without an OpenCTI platform.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

DEFAULT_BUNDLE_URL = "https://tstefan-ws.github.io/deaddrop-hunter/feeds/stix/deaddrop-hunter.bundle.json"
DEFAULT_DURATION_PERIOD = "PT6H"
USER_AGENT = "opencti-connector-deaddrop-hunter/1.0"
MAX_BUNDLE_BYTES = 200 * 1024 * 1024


class BundleError(ValueError):
    """The downloaded document is not a usable STIX 2.1 bundle."""


@dataclass
class FetchResult:
    status: int
    text: str | None = None
    etag: str | None = None
    last_modified: str | None = None

    @property
    def not_modified(self) -> bool:
        return self.status == 304


def fetch_bundle(
    url: str,
    *,
    session: Any = None,
    timeout: float = 60,
    verify: bool = True,
    etag: str | None = None,
    last_modified: str | None = None,
) -> FetchResult:
    """GET the bundle, using conditional request headers from the previous run."""
    if not url or "<" in url or ">" in url:
        raise BundleError(f"DEADDROP_BUNDLE_URL is not configured (got {url!r})")
    if not url.startswith(("https://", "http://", "file://")):
        raise BundleError(f"unsupported URL scheme: {url!r}")
    if url.startswith("file://"):
        return FetchResult(status=200, text=Path(url[len("file://"):]).read_text(encoding="utf-8"))
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    http = session or requests
    resp = http.get(url, headers=headers, timeout=timeout, verify=verify)
    if resp.status_code == 304:
        return FetchResult(status=304, etag=etag, last_modified=last_modified)
    resp.raise_for_status()
    text = resp.text
    if len(text) > MAX_BUNDLE_BYTES:
        raise BundleError(f"bundle too large ({len(text)} bytes)")
    return FetchResult(
        status=resp.status_code,
        text=text,
        etag=resp.headers.get("ETag"),
        last_modified=resp.headers.get("Last-Modified"),
    )


def parse_bundle(text: str) -> dict:
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BundleError(f"bundle is not valid JSON: {exc}") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise BundleError("document is not a STIX bundle (type != 'bundle')")
    if not str(bundle.get("id", "")).startswith("bundle--"):
        raise BundleError("bundle has no valid id")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise BundleError("bundle has no objects array")
    for obj in objects:
        if not isinstance(obj, dict) or "type" not in obj or "id" not in obj:
            raise BundleError("bundle contains an object without type/id")
    return bundle


def bundle_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def transform_bundle(bundle: dict, *, only_current: bool = False) -> dict:
    """Optionally drop indicators no longer served on-chain (``x_opencti_detection`` false).

    Relationships that reference dropped objects are removed too, and report
    ``object_refs`` are pruned so the bundle stays consistent.
    """
    if not only_current:
        return bundle
    dropped = {
        o["id"] for o in bundle["objects"]
        if o.get("type") == "indicator" and o.get("x_opencti_detection") is False
    }
    if not dropped:
        return bundle
    objects = []
    for obj in bundle["objects"]:
        if obj["id"] in dropped:
            continue
        if obj.get("type") == "relationship" and (
            obj.get("source_ref") in dropped or obj.get("target_ref") in dropped
        ):
            dropped.add(obj["id"])
            continue
        objects.append(obj)
    for obj in objects:
        if "object_refs" in obj:
            obj["object_refs"] = [r for r in obj["object_refs"] if r not in dropped]
    return {**bundle, "objects": objects}


_ISO_DURATION = re.compile(
    r"^P(?:(?P<d>\d+)D)?(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+)S)?)?$"
)


def iso_duration_seconds(value: str) -> int:
    """Seconds in a simple ISO-8601 duration (``P1D``, ``PT6H``, ``PT30M``)."""
    match = _ISO_DURATION.match(value or "")
    if not match or not any(match.groupdict().values()):
        raise ValueError(f"invalid ISO-8601 duration: {value!r}")
    g = {k: int(v or 0) for k, v in match.groupdict().items()}
    return g["d"] * 86400 + g["h"] * 3600 + g["m"] * 60 + g["s"]


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def load_config_file(path: Path) -> dict:
    if path.is_file():
        with path.open(encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    return {}


class DeaddropHunterConnector:
    def __init__(self, config: dict | None = None, helper: Any = None, session: Any = None):
        if config is None:
            config = load_config_file(Path(__file__).resolve().parent / "config.yml")
        self.helper = helper or OpenCTIConnectorHelper(config)
        self.bundle_url = get_config_variable(
            "DEADDROP_BUNDLE_URL", ["deaddrop", "bundle_url"], config, default=DEFAULT_BUNDLE_URL
        )
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], config,
            default=DEFAULT_DURATION_PERIOD,
        )
        self.timeout = int(get_config_variable(
            "DEADDROP_TIMEOUT", ["deaddrop", "timeout"], config, isNumber=True, default=60
        ))
        self.verify_ssl = _as_bool(get_config_variable(
            "DEADDROP_VERIFY_SSL", ["deaddrop", "verify_ssl"], config, default=True
        ), True)
        self.only_current = _as_bool(get_config_variable(
            "DEADDROP_ONLY_CURRENT", ["deaddrop", "only_current"], config, default=False
        ), False)
        self.force_reimport = _as_bool(get_config_variable(
            "DEADDROP_FORCE_REIMPORT", ["deaddrop", "force_reimport"], config, default=False
        ), False)
        self.session = session or requests.Session()

    # -- logging helpers (connector_logger exists in pycti >= 6.0) -----------------
    def _log(self, level: str, msg: str) -> None:
        logger = getattr(self.helper, "connector_logger", None)
        if logger is not None:
            getattr(logger, level)(msg)
        else:  # pragma: no cover - very old pycti
            getattr(self.helper, f"log_{level}")(msg)

    def process_message(self) -> None:
        now = datetime.now(UTC)
        state = dict(self.helper.get_state() or {})
        try:
            self._log("info", f"[deaddrop-hunter] fetching {self.bundle_url}")
            result = fetch_bundle(
                self.bundle_url,
                session=self.session,
                timeout=self.timeout,
                verify=self.verify_ssl,
                etag=None if self.force_reimport else state.get("etag"),
                last_modified=None if self.force_reimport else state.get("last_modified"),
            )
            state["last_run"] = now.isoformat()
            if result.not_modified:
                self._log("info", "[deaddrop-hunter] feed not modified since last run")
                self.helper.set_state(state)
                return
            assert result.text is not None
            digest = bundle_sha256(result.text)
            if digest == state.get("last_sha256") and not self.force_reimport:
                self._log("info", "[deaddrop-hunter] bundle unchanged (same sha256), skipping")
                state.update(etag=result.etag, last_modified=result.last_modified)
                self.helper.set_state(state)
                return
            bundle = transform_bundle(parse_bundle(result.text), only_current=self.only_current)

            friendly_name = f"deaddrop-hunter run @ {now.strftime('%Y-%m-%d %H:%M:%S')}"
            work_id = self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)
            try:
                self.helper.send_stix2_bundle(
                    json.dumps(bundle),
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
            except Exception as exc:
                self.helper.api.work.to_processed(work_id, f"failed: {exc}", in_error=True)
                raise
            message = (
                f"[deaddrop-hunter] sent {len(bundle['objects'])} STIX objects "
                f"(sha256 {digest[:12]})"
            )
            self.helper.api.work.to_processed(work_id, message)
            self._log("info", message)
            state.update(
                last_sha256=digest,
                etag=result.etag,
                last_modified=result.last_modified,
                last_success=now.isoformat(),
            )
            self.helper.set_state(state)
        except (KeyboardInterrupt, SystemExit):
            self._log("info", "[deaddrop-hunter] connector stopped")
            sys.exit(0)
        except Exception as exc:
            self._log("error", f"[deaddrop-hunter] run failed: {exc}")

    def run(self) -> None:
        if hasattr(self.helper, "schedule_iso"):
            self.helper.schedule_iso(
                message_callback=self.process_message, duration_period=self.duration_period
            )
            return
        seconds = iso_duration_seconds(self.duration_period)
        for name in ("schedule_process", "schedule_period"):
            if hasattr(self.helper, name):
                getattr(self.helper, name)(message_callback=self.process_message, duration_period=seconds)
                return
        while True:  # pragma: no cover - fallback for pycti without schedulers
            self.process_message()
            time.sleep(seconds)
