"""Unit tests for connectors/opencti with pycti mocked (no OpenCTI platform needed)."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

pytest.importorskip("requests")
pytest.importorskip("yaml")

CONNECTOR_SRC = Path(__file__).resolve().parents[2] / "connectors" / "opencti" / "src" / "connector.py"


def _get_config_variable(env_var, yaml_path, config=None, isNumber=False, default=None, required=False):
    node = config or {}
    for key in yaml_path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return int(node) if isNumber else node


@pytest.fixture(scope="module")
def conn_mod():
    fake = types.ModuleType("pycti")
    fake.OpenCTIConnectorHelper = mock.MagicMock(name="OpenCTIConnectorHelper")
    fake.get_config_variable = _get_config_variable
    name = "ddh_opencti_connector"
    with mock.patch.dict(sys.modules, {"pycti": fake}):
        spec = importlib.util.spec_from_file_location(name, CONNECTOR_SRC)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module  # dataclasses need the module registered
        spec.loader.exec_module(module)
        yield module


class FakeResponse:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, headers=None, timeout=None, verify=None):
        self.calls.append({"url": url, "headers": headers or {}, "timeout": timeout, "verify": verify})
        return self.responses.pop(0)


def _helper(state=None):
    helper = mock.MagicMock()
    helper.connect_id = "connector-id"
    helper.get_state.return_value = state
    helper.api.work.initiate_work.return_value = "work-1"
    return helper


@pytest.fixture
def bundle_text(bundle):
    return json.dumps(bundle)


def test_fetch_sends_conditional_headers(conn_mod):
    session = FakeSession(FakeResponse(304))
    res = conn_mod.fetch_bundle("https://x.example/b.json", session=session, etag='"abc"',
                                last_modified="Mon, 19 Oct 2026 12:00:00 GMT")
    assert res.not_modified
    assert session.calls[0]["headers"]["If-None-Match"] == '"abc"'
    assert session.calls[0]["headers"]["If-Modified-Since"].startswith("Mon")


def test_fetch_rejects_placeholder_and_bad_scheme(conn_mod):
    with pytest.raises(conn_mod.BundleError):
        conn_mod.fetch_bundle("https://<github-user>.github.io/x.json", session=FakeSession())
    with pytest.raises(conn_mod.BundleError):
        conn_mod.fetch_bundle("ftp://x.example/b.json", session=FakeSession())


def test_parse_bundle_validation(conn_mod, bundle_text):
    assert conn_mod.parse_bundle(bundle_text)["type"] == "bundle"
    for bad in ("not json", "[]", '{"type": "report"}', '{"type": "bundle", "id": "bundle--x"}'):
        with pytest.raises(conn_mod.BundleError):
            conn_mod.parse_bundle(bad)


def test_transform_only_current(conn_mod, bundle):
    out = conn_mod.transform_bundle(json.loads(json.dumps(bundle)), only_current=True)
    ids = {o["id"] for o in out["objects"]}
    inds = [o for o in out["objects"] if o["type"] == "indicator"]
    assert inds and all(o["x_opencti_detection"] for o in inds)
    assert len(inds) < len([o for o in bundle["objects"] if o["type"] == "indicator"])
    for o in out["objects"]:
        for ref in [o.get("source_ref"), o.get("target_ref"), *o.get("object_refs", [])]:
            assert ref is None or ref in ids
    assert conn_mod.transform_bundle(bundle, only_current=False) is bundle


def test_iso_duration(conn_mod):
    assert conn_mod.iso_duration_seconds("PT6H") == 21600
    assert conn_mod.iso_duration_seconds("P1DT30M") == 88200
    with pytest.raises(ValueError):
        conn_mod.iso_duration_seconds("6h")


def test_process_message_sends_bundle(conn_mod, bundle_text):
    helper = _helper(state=None)
    session = FakeSession(FakeResponse(200, bundle_text, {"ETag": '"v1"'}))
    c = conn_mod.DeaddropHunterConnector(config={}, helper=helper, session=session)
    assert c.bundle_url == conn_mod.DEFAULT_BUNDLE_URL
    c.process_message()
    helper.api.work.initiate_work.assert_called_once()
    args, kwargs = helper.send_stix2_bundle.call_args
    assert json.loads(args[0])["type"] == "bundle"
    assert kwargs["work_id"] == "work-1"
    helper.api.work.to_processed.assert_called_once()
    state = helper.set_state.call_args[0][0]
    assert state["etag"] == '"v1"'
    assert state["last_sha256"] == conn_mod.bundle_sha256(bundle_text)
    assert "last_run" in state and "last_success" in state


def test_process_message_skips_unchanged(conn_mod, bundle_text):
    digest = conn_mod.bundle_sha256(bundle_text)
    helper = _helper(state={"last_sha256": digest, "etag": '"v1"'})
    session = FakeSession(FakeResponse(200, bundle_text, {"ETag": '"v2"'}))
    conn_mod.DeaddropHunterConnector(config={}, helper=helper, session=session).process_message()
    helper.send_stix2_bundle.assert_not_called()
    assert session.calls[0]["headers"]["If-None-Match"] == '"v1"'


def test_process_message_not_modified(conn_mod):
    helper = _helper(state={"etag": '"v1"'})
    session = FakeSession(FakeResponse(304))
    conn_mod.DeaddropHunterConnector(config={}, helper=helper, session=session).process_message()
    helper.api.work.initiate_work.assert_not_called()
    helper.set_state.assert_called_once()


def test_process_message_marks_work_in_error(conn_mod, bundle_text):
    helper = _helper()
    helper.send_stix2_bundle.side_effect = RuntimeError("boom")
    session = FakeSession(FakeResponse(200, bundle_text))
    conn_mod.DeaddropHunterConnector(config={}, helper=helper, session=session).process_message()
    helper.api.work.to_processed.assert_called_once_with("work-1", "failed: boom", in_error=True)
    helper.connector_logger.error.assert_called()
    helper.set_state.assert_not_called()


def test_config_from_yaml_dict(conn_mod):
    cfg = {"connector": {"duration_period": "PT1H"},
           "deaddrop": {"bundle_url": "https://feeds.example/b.json", "only_current": "true", "timeout": 5}}
    c = conn_mod.DeaddropHunterConnector(config=cfg, helper=_helper(), session=FakeSession())
    assert c.bundle_url == "https://feeds.example/b.json"
    assert c.only_current is True and c.timeout == 5 and c.duration_period == "PT1H"


def test_run_uses_schedule_iso(conn_mod):
    helper = _helper()
    c = conn_mod.DeaddropHunterConnector(config={}, helper=helper, session=FakeSession())
    c.run()
    helper.schedule_iso.assert_called_once_with(message_callback=c.process_message, duration_period="PT6H")
