"""
Unit tests for stubsmith.cli (stubsmith pull command).

All tests are hermetic - no network required.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import unittest
from unittest.mock import MagicMock, patch

from stubsmith.cli import main


# ---------------------------------------------------------------------------
# Sample bundle payloads
# ---------------------------------------------------------------------------

def _make_variant(status=200, body='{"ok":true}', body_capped=False, count=3):
    v = {
        "body": body,
        "count": count,
        "duration_ms": 42,
        "headers": {"content-type": "application/json"},
        "status": status,
    }
    if body_capped:
        v["body_capped"] = True
    return v


def _make_stub(fingerprint="abc123", degraded=False, variants=None):
    return {
        "degraded": degraded,
        "field_rules": [],
        "fingerprint": fingerprint,
        "key_paths": [],
        "variants": variants or [_make_variant()],
    }


def _make_endpoint(domain="api.example.com", method="GET", path_template="/api/users", stubs=None):
    return {
        "domain": domain,
        "fingerprint_value_paths": [],
        "is_dynamic": False,
        "method": method,
        "path_template": path_template,
        "stubs": stubs or [_make_stub()],
    }


def _make_bundle(endpoints=None, truncated=None, cursor="42"):
    b = {
        "cursor": cursor,
        "endpoints": endpoints or [_make_endpoint()],
        "generated_at": "2024-01-15T10:00:00.000Z",
        "ok": True,
        "version": 1,
    }
    if truncated is not None:
        b["truncated"] = truncated
    return b


def _urlopen_mock(bundle_dict):
    """Return a mock for urllib.request.urlopen that yields bundle_dict as JSON."""
    data = json.dumps(bundle_dict).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = data
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _http_error(code, body=b'{"error":"oops"}'):
    return urllib.error.HTTPError(
        url="http://localhost:3000/v1/replay/bundle",
        code=code,
        msg="Error",
        hdrs=None,
        fp=MagicMock(read=lambda: body),
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Subcommand dispatch - regression tests for the argument-vector contract
# ---------------------------------------------------------------------------

class TestSubcommandDispatch(unittest.TestCase):
    """
    The console script receives sys.argv[1:], so the user runs::

        stubsmith pull [options]

    meaning argv is always ["pull", ...].  Calling main(["pull"]) is the
    minimal regression test for the bug where main([]) silently ran a pull
    and main(["pull"]) was rejected as an unrecognized argument.
    """

    def test_pull_subcommand_succeeds(self):
        """main(["pull"]) must reach the pull logic, not error on "pull"."""
        import tempfile
        bundle = _make_bundle()
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(bundle)):
                    code = main(["pull", "--out", out])
            self.assertEqual(code, 0)
            self.assertTrue(pathlib.Path(out).exists())

    def test_no_subcommand_exits_nonzero(self):
        """main([]) must print help and return non-zero - not silently pull."""
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as ctx:
                main([])
        self.assertNotEqual(ctx.exception.code, 0)

    def test_unknown_subcommand_exits_nonzero(self):
        """main(["bogus"]) must report an invalid choice, not "unrecognized arguments"."""
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            with self.assertRaises(SystemExit) as ctx:
                main(["bogus"])
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn("bogus", mock_err.getvalue())


class TestPullHappyPath(unittest.TestCase):

    def _run(self, tmp_path, bundle=None, extra_argv=None):
        """Run main() with a mocked urlopen; return (exit_code, written_data)."""
        bundle = bundle or _make_bundle()
        out = str(tmp_path / "bundle.json")
        argv = ["pull", "--out", out] + (extra_argv or [])
        with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
            with patch("urllib.request.urlopen", return_value=_urlopen_mock(bundle)):
                code = main(argv)
        return code, out

    def test_exit_zero_on_success(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            code, out = self._run(pathlib.Path(d))
        self.assertEqual(code, 0)

    def test_writes_valid_json(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            code, out = self._run(pathlib.Path(d))
            self.assertEqual(code, 0)
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
        self.assertTrue(data["ok"])
        self.assertIn("endpoints", data)

    def test_file_has_trailing_newline(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            _, out = self._run(pathlib.Path(d))
            with open(out, encoding="utf-8") as fh:
                content = fh.read()
        self.assertTrue(content.endswith("\n"))

    def test_deterministic_across_shuffled_input(self):
        """Two pulls with the same data in different orderings must produce identical bytes."""
        import tempfile

        # Both bundles contain the same logical data:
        # - endpoint a.example.com GET /a with stubs fff and aaa, fff having variants 200 and 500
        # - endpoint b.example.com POST /b with one stub
        #
        # bundle1: endpoints in order [b, a], stubs in order [fff, aaa], variants in order [500, 200]
        # bundle2: endpoints in order [a, b], stubs in order [aaa, fff], variants in order [200, 500]
        # After sorting they must be identical.

        ep_a = _make_endpoint(
            domain="a.example.com", method="GET", path_template="/a",
            stubs=[
                _make_stub(fingerprint="fff", variants=[_make_variant(500), _make_variant(200)]),
                _make_stub(fingerprint="aaa"),
            ],
        )
        ep_b = _make_endpoint(domain="b.example.com", method="POST", path_template="/b")
        bundle1 = _make_bundle(endpoints=[ep_b, ep_a])  # b before a

        ep_a2 = _make_endpoint(
            domain="a.example.com", method="GET", path_template="/a",
            stubs=[
                _make_stub(fingerprint="aaa"),
                _make_stub(fingerprint="fff", variants=[_make_variant(200), _make_variant(500)]),
            ],
        )
        ep_b2 = _make_endpoint(domain="b.example.com", method="POST", path_template="/b")
        bundle2 = _make_bundle(endpoints=[ep_a2, ep_b2])  # a before b

        with tempfile.TemporaryDirectory() as d:
            out1 = str(pathlib.Path(d) / "b1.json")
            out2 = str(pathlib.Path(d) / "b2.json")

            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(bundle1)):
                    main(["pull", "--out", out1])
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(bundle2)):
                    main(["pull", "--out", out2])

            with open(out1, encoding="utf-8") as f1, open(out2, encoding="utf-8") as f2:
                content1 = f1.read()
                content2 = f2.read()

        self.assertEqual(content1, content2, "Determinism check failed - outputs differ")

    def test_keys_sorted_in_output(self):
        """json.dumps with sort_keys=True must produce key-sorted dicts."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            _, out = self._run(pathlib.Path(d))
            with open(out, encoding="utf-8") as fh:
                content = fh.read()
        # 'cursor' < 'endpoints' < 'generated_at' < 'ok' < 'version' alphabetically
        cursor_pos = content.index('"cursor"')
        endpoints_pos = content.index('"endpoints"')
        generated_pos = content.index('"generated_at"')
        self.assertLess(cursor_pos, endpoints_pos)
        self.assertLess(endpoints_pos, generated_pos)


# ---------------------------------------------------------------------------
# --out flag and parent directory creation
# ---------------------------------------------------------------------------

class TestOutFlag(unittest.TestCase):

    def test_out_flag_respected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "custom.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(_make_bundle())):
                    code = main(["pull", "--out", out])
            self.assertEqual(code, 0)
            self.assertTrue(pathlib.Path(out).exists())

    def test_parent_directory_created(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "deep" / "nested" / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(_make_bundle())):
                    code = main(["pull", "--out", out])
            self.assertEqual(code, 0)
            self.assertTrue(pathlib.Path(out).exists())


# ---------------------------------------------------------------------------
# --endpoint filter
# ---------------------------------------------------------------------------

class TestEndpointFilter(unittest.TestCase):

    def test_endpoint_produces_correct_query_params(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(_make_bundle())) as mopen:
                    main(["pull", "--out", out, "--endpoint", "GET /api/users/{id}"])
            called_url = mopen.call_args[0][0].full_url
        self.assertIn("method=GET", called_url)
        self.assertIn("path=%2Fapi%2Fusers%2F%7Bid%7D", called_url)

    def test_endpoint_method_uppercased(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(_make_bundle())) as mopen:
                    main(["pull", "--out", out, "--endpoint", "post /v1/charges"])
            called_url = mopen.call_args[0][0].full_url
        self.assertIn("method=POST", called_url)


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestMissingApiKey(unittest.TestCase):

    def test_missing_key_exits_nonzero(self):
        backup = os.environ.pop("STUBSMITH_API_KEY", None)
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as d:
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    code = main(["pull", "--out", str(pathlib.Path(d) / "b.json")])
                self.assertEqual(code, 1)
                self.assertIn("STUBSMITH_API_KEY", mock_stderr.getvalue())
        finally:
            if backup is not None:
                os.environ["STUBSMITH_API_KEY"] = backup


class TestHttpErrors(unittest.TestCase):

    def _run_with_http_error(self, status_code, tmp_path):
        out = str(tmp_path / "bundle.json")
        err = _http_error(status_code)
        with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
            with patch("urllib.request.urlopen", side_effect=err):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
                    code = main(["pull", "--out", out])
        return code, mock_err.getvalue()

    def test_401_exits_nonzero_with_status(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            code, stderr = self._run_with_http_error(401, pathlib.Path(d))
        self.assertNotEqual(code, 0)
        self.assertIn("401", stderr)

    def test_500_exits_nonzero_with_status(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            code, stderr = self._run_with_http_error(500, pathlib.Path(d))
        self.assertNotEqual(code, 0)
        self.assertIn("500", stderr)


class TestMalformedJson(unittest.TestCase):

    def test_malformed_json_exits_nonzero(self):
        import tempfile
        bad_resp = MagicMock()
        bad_resp.read.return_value = b"this is not json {{{"
        bad_resp.__enter__ = lambda s: s
        bad_resp.__exit__ = MagicMock(return_value=False)

        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=bad_resp):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        code = main(["pull", "--out", out])
            self.assertNotEqual(code, 0)
            # No partial file must be left behind
            self.assertFalse(pathlib.Path(out).exists())

    def test_no_partial_file_on_malformed_json(self):
        """A pre-existing bundle must not be corrupted by a bad pull."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "bundle.json"
            original_content = '{"ok": true, "endpoints": [], "cursor": "old"}\n'
            out.write_text(original_content, encoding="utf-8")

            bad_resp = MagicMock()
            bad_resp.read.return_value = b"not json"
            bad_resp.__enter__ = lambda s: s
            bad_resp.__exit__ = MagicMock(return_value=False)

            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=bad_resp):
                    with patch("sys.stderr", new_callable=io.StringIO):
                        main(["pull", "--out", str(out)])

            # Original file must be intact
            self.assertEqual(out.read_text(encoding="utf-8"), original_content)


# ---------------------------------------------------------------------------
# Summary: truncated, degraded, body_capped
# ---------------------------------------------------------------------------

class TestSummaryWarnings(unittest.TestCase):

    def _run_capture_stdout(self, bundle, tmp_path):
        out = str(tmp_path / "bundle.json")
        with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
            with patch("urllib.request.urlopen", return_value=_urlopen_mock(bundle)):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                    code = main(["pull", "--out", out])
        return code, mock_out.getvalue()

    def test_truncated_stubs_surfaced(self):
        import tempfile
        trunc = {"stubs": {"dropped": 17, "limit": 2000}}
        bundle = _make_bundle(truncated=trunc)
        with tempfile.TemporaryDirectory() as d:
            code, stdout = self._run_capture_stdout(bundle, pathlib.Path(d))
        self.assertEqual(code, 0)
        self.assertIn("truncated", stdout.lower())
        # Assert on the exact warning phrase, not a bare digit that could collide
        # with the cursor or summary counts.
        self.assertIn("17 stubs dropped", stdout)

    def test_truncated_variants_surfaced(self):
        import tempfile
        trunc = {
            "variants": [
                {"endpoint": "||GET|/foo", "fingerprint": "abc", "dropped": 3, "limit": 10},
                {"endpoint": "||GET|/bar", "fingerprint": "def", "dropped": 1, "limit": 10},
            ]
        }
        bundle = _make_bundle(truncated=trunc)
        with tempfile.TemporaryDirectory() as d:
            code, stdout = self._run_capture_stdout(bundle, pathlib.Path(d))
        self.assertEqual(code, 0)
        self.assertIn("truncated", stdout.lower())
        # "4" appears in cursor="42" too - assert the full phrase from the variants branch.
        self.assertIn("4 variant(s) dropped across", stdout)

    def test_truncated_body_bytes_surfaced(self):
        import tempfile
        trunc = {"body_bytes": {"capped": 2, "limit": 102400}}
        bundle = _make_bundle(truncated=trunc)
        with tempfile.TemporaryDirectory() as d:
            code, stdout = self._run_capture_stdout(bundle, pathlib.Path(d))
        self.assertEqual(code, 0)
        # "2" and "body" both appear in the summary header; assert the phrase
        # unique to this code path so the test cannot pass with this branch deleted.
        self.assertIn("2 variant body/bodies omitted", stdout)

    def test_degraded_stubs_surfaced(self):
        import tempfile
        ep = _make_endpoint(stubs=[_make_stub(degraded=True), _make_stub(degraded=True, fingerprint="xyz")])
        bundle = _make_bundle(endpoints=[ep])
        with tempfile.TemporaryDirectory() as d:
            code, stdout = self._run_capture_stdout(bundle, pathlib.Path(d))
        self.assertEqual(code, 0)
        # "2" appears in cursor="42" - assert the full warning phrase.
        self.assertIn("2 stub(s) marked degraded", stdout)

    def test_body_capped_variants_surfaced(self):
        import tempfile
        stub = _make_stub(variants=[_make_variant(body_capped=True), _make_variant(status=500, body_capped=True)])
        ep = _make_endpoint(stubs=[stub])
        bundle = _make_bundle(endpoints=[ep])
        with tempfile.TemporaryDirectory() as d:
            code, stdout = self._run_capture_stdout(bundle, pathlib.Path(d))
        self.assertEqual(code, 0)
        # "2" appears in cursor="42" - assert the full warning phrase.
        self.assertIn("2 variant(s) have body_capped=true", stdout)


# ---------------------------------------------------------------------------
# Collision case: two endpoints share one fingerprint hash
# ---------------------------------------------------------------------------

class TestFingerprintCollision(unittest.TestCase):
    """
    Verifies that endpoints sharing a fingerprint hash are kept distinct.

    In one catalog run, GET /api/products, GET /api/users/{id},
    GET /api/orders/{id}, and three /avatars/*.png all shared the hash
    fc552c95a0bb0d3e because every body-less GET has an identical structural
    fingerprint.  The file must preserve endpoint → stub nesting so replay()
    can distinguish them by the composite (domain, method, path_template, fingerprint).
    """

    SHARED_HASH = "fc552c95a0bb0d3e"

    def _collision_bundle(self):
        ep_products = _make_endpoint(
            domain="api.example.com", method="GET", path_template="/api/products",
            stubs=[_make_stub(fingerprint=self.SHARED_HASH, variants=[_make_variant(200, '{"products":[]}')])],
        )
        ep_users = _make_endpoint(
            domain="api.example.com", method="GET", path_template="/api/users/{id}",
            stubs=[_make_stub(fingerprint=self.SHARED_HASH, variants=[_make_variant(200, '{"user":"alice"}')])],
        )
        return _make_bundle(endpoints=[ep_products, ep_users])

    def test_collision_bundle_has_two_endpoints(self):
        import tempfile
        bundle = self._collision_bundle()
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(bundle)):
                    code = main(["pull", "--out", out])
            self.assertEqual(code, 0)
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)

        endpoints = data["endpoints"]
        self.assertEqual(len(endpoints), 2, "Both endpoints must survive; collision must not merge them")

    def test_collision_stubs_are_distinguishable(self):
        """Both stubs must be retrievable by their path_template."""
        import tempfile
        bundle = self._collision_bundle()
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(bundle)):
                    main(["pull", "--out", out])
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)

        by_path = {ep["path_template"]: ep for ep in data["endpoints"]}
        self.assertIn("/api/products", by_path)
        self.assertIn("/api/users/{id}", by_path)

        products_body = by_path["/api/products"]["stubs"][0]["variants"][0]["body"]
        users_body    = by_path["/api/users/{id}"]["stubs"][0]["variants"][0]["body"]
        self.assertNotEqual(products_body, users_body,
                             "Bodies must be distinct (different stubs, same fingerprint hash)")

    def test_collision_round_trips_both_stubs(self):
        """All stubs must appear verbatim in the on-disk file."""
        import tempfile
        bundle = self._collision_bundle()
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(bundle)):
                    main(["pull", "--out", out])
            with open(out, encoding="utf-8") as fh:
                content = fh.read()

        # Both fingerprints must appear - each endpoint's stub must survive
        self.assertEqual(content.count(self.SHARED_HASH), 2,
                         "Each endpoint carries its own stub; both must appear")


# ---------------------------------------------------------------------------
# SDK public default constants
# ---------------------------------------------------------------------------

class TestSdkPublicDefaults(unittest.TestCase):
    """
    Verify that stubsmith exposes public URL constants and that the example
    script's resolved ingest URL matches the SDK constant when no env vars
    are set.  A divergence between the two was the root cause of the
    connection-refused bug that stayed hidden while the example used the
    correct hosted URL and the SDK defaulted to localhost.
    """

    def test_default_ingest_url_is_hosted(self):
        import stubsmith
        self.assertEqual(
            stubsmith.DEFAULT_INGEST_URL,
            "https://ingest.stubsmith.dev/v1/captures",
        )

    def test_default_api_url_is_hosted(self):
        import stubsmith
        self.assertEqual(
            stubsmith.DEFAULT_API_URL,
            "https://app.stubsmith.dev/api",
        )

    def _load_traffic_module(self, extra_env=None):
        """Load generate_traffic.py as a module, return it or None on failure."""
        import importlib.util
        import sys
        from unittest.mock import MagicMock

        spec = importlib.util.spec_from_file_location(
            "_gen_traffic_" + str(id(extra_env)),
            str(
                pathlib.Path(__file__).parent.parent
                / "examples/fixtures-testing/generate_traffic.py"
            ),
        )
        env_keys = ("STUBSMITH_INGEST_URL", "STUBSMITH_API_URL", "STUBSMITH_BACKEND_URL")
        env_backup = {k: os.environ.pop(k) for k in env_keys if k in os.environ}
        try:
            patch_env = patch.dict(os.environ, extra_env or {})
            patch_mods = patch.dict(sys.modules, {
                "shopclient": MagicMock(),
                "shopclient.client": MagicMock(),
                "shopclient.errors": MagicMock(),
            })
            with patch_env, patch_mods:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
            return mod
        except Exception:
            return None
        finally:
            os.environ.update(env_backup)

    def test_example_ingest_url_matches_sdk_default_no_env(self):
        """With no env vars, the example resolves _INGEST_URL to the SDK constant."""
        import stubsmith
        mod = self._load_traffic_module()
        if mod is None:
            return  # loading failed due to missing deps - skip
        self.assertEqual(
            mod._INGEST_URL,
            stubsmith.DEFAULT_INGEST_URL,
            "Example's _INGEST_URL must equal stubsmith.DEFAULT_INGEST_URL when no env vars are set",
        )

    def test_example_ingest_url_unaffected_by_trailing_slash_on_api_url(self):
        """STUBSMITH_API_URL with a trailing slash must not contaminate _INGEST_URL."""
        import stubsmith
        mod = self._load_traffic_module(
            extra_env={"STUBSMITH_API_URL": "https://app.stubsmith.dev/api/"}
        )
        if mod is None:
            return
        self.assertEqual(
            mod._INGEST_URL,
            stubsmith.DEFAULT_INGEST_URL,
            "_INGEST_URL must still be the SDK default even when STUBSMITH_API_URL has a trailing slash",
        )


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Real entry points
#
# Everything above calls main() in-process, which cannot catch breakage in the
# console script or the ``python -m`` shim: argument dispatch, import errors and
# the exit-code path all live outside main(). These tests spawn a subprocess so
# the entry point actually runs.
# ---------------------------------------------------------------------------

class ModuleEntryPointTests(unittest.TestCase):
    """``python -m stubsmith`` behaves like the console script."""

    def _run(self, *args, **env):
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        child_env = dict(os.environ)
        # Drop any real credentials/URLs from the developer's shell so the test
        # exercises defaults rather than whatever happens to be exported.
        for k in ("STUBSMITH_API_KEY", "STUBSMITH_API_URL", "STUBSMITH_BACKEND_URL"):
            child_env.pop(k, None)
        child_env.update(env)
        return subprocess.run(
            [sys.executable, "-m", "stubsmith", *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=60,
            env=child_env,
        )

    def test_help_exits_zero_and_lists_pull(self):
        proc = self._run("--help")
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("pull", proc.stdout)

    def test_pull_subcommand_is_dispatched(self):
        # Points at a closed port so the command reaches the network layer and
        # fails there, which proves argument dispatch worked. A dispatch failure
        # exits 2 with a usage error instead, so the two are distinguishable.
        proc = self._run(
            "pull",
            STUBSMITH_API_URL="http://127.0.0.1:1",
            STUBSMITH_API_KEY="dummy-not-a-real-key",
        )
        self.assertNotEqual(proc.returncode, 0)
        combined = proc.stdout + proc.stderr
        self.assertNotIn("unrecognized arguments", combined)
        self.assertIn("Network error", combined)

    def test_pull_without_api_key_fails_before_the_network(self):
        proc = self._run("pull")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("STUBSMITH_API_KEY", proc.stdout + proc.stderr)

    def test_unknown_subcommand_is_rejected(self):
        proc = self._run("frobnicate")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid choice", proc.stdout + proc.stderr)

    def test_pull_default_api_url_is_the_hosted_service(self):
        # Guards the localhost-default regression: a stale default silently
        # points every new user's ``stubsmith pull`` at their own machine.
        # Asserted on the resolved value rather than help text, which never
        # mentioned the URL.
        from stubsmith.cli import _resolve_api_url

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_resolve_api_url(), "https://app.stubsmith.dev/api")


# ---------------------------------------------------------------------------
# --samples / fetch_bundle
# ---------------------------------------------------------------------------

class TestSamplesFlag(unittest.TestCase):

    def _pull(self, *extra):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen", return_value=_urlopen_mock(_make_bundle())) as mopen:
                    code = main(["pull", "--out", out, *extra])
            url = mopen.call_args[0][0].full_url if mopen.call_args else None
        return code, url

    def test_absent_by_default(self):
        """A plain pull must not start asking for windows: the server's default
        is one recording per response and the bundle stays small."""
        code, url = self._pull()
        self.assertEqual(code, 0)
        self.assertNotIn("samples", url)

    def test_all_is_forwarded(self):
        code, url = self._pull("--endpoint", "GET /api/orders", "--samples", "all")
        self.assertEqual(code, 0)
        self.assertIn("samples=all", url)

    def test_integer_is_forwarded(self):
        code, url = self._pull("--endpoint", "GET /api/orders", "--samples", "5")
        self.assertEqual(code, 0)
        self.assertIn("samples=5", url)

    def test_one_needs_no_endpoint(self):
        code, url = self._pull("--samples", "1")
        self.assertEqual(code, 0)
        self.assertIn("samples=1", url)

    def test_above_one_without_endpoint_is_rejected_locally(self):
        """Rejected before the request so the message names --endpoint rather
        than surfacing as an opaque HTTP 400."""
        with patch("sys.stderr", new_callable=io.StringIO) as err:
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen") as mopen:
                    code = main(["pull", "--samples", "all"])
        self.assertEqual(code, 1)
        self.assertIn("--endpoint", err.getvalue())
        mopen.assert_not_called()

    def test_garbage_is_rejected(self):
        for value in ("lots", "0", "-2", "1.5"):
            with self.subTest(value=value):
                with patch("sys.stderr", new_callable=io.StringIO) as err:
                    with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                        with patch("urllib.request.urlopen") as mopen:
                            code = main(["pull", "--endpoint", "GET /x", "--samples", value])
                self.assertEqual(code, 1)
                self.assertIn("--samples", err.getvalue())
                mopen.assert_not_called()


class TestFetchBundle(unittest.TestCase):

    def test_returns_the_parsed_bundle(self):
        import stubsmith
        bundle = _make_bundle()
        with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
            with patch("urllib.request.urlopen", return_value=_urlopen_mock(bundle)):
                got = stubsmith.fetch_bundle("GET /api/orders", samples="all")
        self.assertEqual(got["endpoints"], bundle["endpoints"])

    def test_forwards_endpoint_and_samples(self):
        import stubsmith
        with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
            with patch("urllib.request.urlopen", return_value=_urlopen_mock(_make_bundle())) as mopen:
                stubsmith.fetch_bundle("get /api/orders", samples=3)
        url = mopen.call_args[0][0].full_url
        self.assertIn("method=GET", url)
        self.assertIn("samples=3", url)

    def test_explicit_api_key_beats_the_environment(self):
        import stubsmith
        with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-from-env"}):
            with patch("urllib.request.urlopen", return_value=_urlopen_mock(_make_bundle())) as mopen:
                stubsmith.fetch_bundle(api_key="sk-explicit")
        header = mopen.call_args[0][0].get_header("Authorization")
        self.assertEqual(header, "Bearer sk-explicit")

    def test_no_key_anywhere_raises(self):
        import stubsmith
        backup = os.environ.pop("STUBSMITH_API_KEY", None)
        try:
            with self.assertRaisesRegex(RuntimeError, "STUBSMITH_API_KEY"):
                stubsmith.fetch_bundle()
        finally:
            if backup is not None:
                os.environ["STUBSMITH_API_KEY"] = backup

    def test_malformed_endpoint_raises(self):
        import stubsmith
        with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
            with self.assertRaisesRegex(ValueError, "METHOD /path"):
                stubsmith.fetch_bundle("/api/orders")

    def test_samples_above_one_without_endpoint_raises(self):
        import stubsmith
        with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
            with self.assertRaisesRegex(ValueError, "requires an endpoint"):
                stubsmith.fetch_bundle(samples="all")

    def test_bad_samples_value_raises(self):
        import stubsmith
        with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
            with self.assertRaisesRegex(ValueError, "positive integer"):
                stubsmith.fetch_bundle("GET /x", samples="lots")


# ---------------------------------------------------------------------------
# Repeated --endpoint
#
# --samples above 1 is not served project-wide, so a sample window covering
# several endpoints can only come from one request per endpoint. Without this
# the user hand-merges JSON.
# ---------------------------------------------------------------------------

class TestMultipleEndpoints(unittest.TestCase):

    @staticmethod
    def _ep(path, fingerprint, domain="api.example.com", method="GET"):
        return {
            "domain": domain, "method": method, "path_template": path,
            "is_dynamic": False, "fingerprint_value_paths": [],
            "stubs": [{"fingerprint": fingerprint, "key_paths": [], "field_rules": [],
                       "degraded": False, "variants": [
                           {"status": 200, "count": 1, "duration_ms": 1,
                            "headers": {}, "body": "{}"}]}],
        }

    def _pull(self, extra, responses):
        import tempfile, json as _json
        with tempfile.TemporaryDirectory() as d:
            out = str(pathlib.Path(d) / "bundle.json")
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen",
                           side_effect=[_urlopen_mock(r) for r in responses]) as mopen:
                    code = main(["pull", "--out", out, *extra])
            written = _json.loads(pathlib.Path(out).read_text()) if code == 0 else None
            urls = [c[0][0].full_url for c in mopen.call_args_list]
        return code, written, urls

    def test_two_endpoints_produce_two_requests_merged_into_one_bundle(self):
        code, bundle, urls = self._pull(
            ["--endpoint", "GET /a", "--endpoint", "GET /b", "--samples", "all"],
            # Higher cursor first, so "max" and "last" cannot be confused.
            [_make_bundle([self._ep("/a", "fpa")], cursor="9"),
             _make_bundle([self._ep("/b", "fpb")], cursor="4")],
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(urls), 2)
        self.assertIn("path=%2Fa", urls[0])
        self.assertIn("path=%2Fb", urls[1])
        self.assertTrue(all("samples=all" in u for u in urls))

        paths = sorted(e["path_template"] for e in bundle["endpoints"])
        self.assertEqual(paths, ["/a", "/b"])
        # cursor is the max across parts, matching the server's own rule
        self.assertEqual(bundle["cursor"], "9")

    def test_the_same_endpoint_twice_does_not_duplicate_stubs(self):
        """Overlapping filters must not yield two stubs with one identity."""
        code, bundle, _ = self._pull(
            ["--endpoint", "GET /a", "--endpoint", "GET /a"],
            [_make_bundle([self._ep("/a", "fpa")]),
             _make_bundle([self._ep("/a", "fpa")])],
        )
        self.assertEqual(code, 0)
        self.assertEqual(len(bundle["endpoints"]), 1)
        self.assertEqual(len(bundle["endpoints"][0]["stubs"]), 1)

    def test_distinct_shapes_on_one_endpoint_are_both_kept(self):
        code, bundle, _ = self._pull(
            ["--endpoint", "GET /a", "--endpoint", "GET /a"],
            [_make_bundle([self._ep("/a", "fp1")]),
             _make_bundle([self._ep("/a", "fp2")])],
        )
        self.assertEqual(code, 0)
        fps = sorted(s["fingerprint"] for s in bundle["endpoints"][0]["stubs"])
        self.assertEqual(fps, ["fp1", "fp2"])

    def test_a_truncated_report_survives_the_merge(self):
        """A partial pull must still say it was partial."""
        code, bundle, _ = self._pull(
            ["--endpoint", "GET /a", "--endpoint", "GET /b"],
            [_make_bundle([self._ep("/a", "fpa")]),
             _make_bundle([self._ep("/b", "fpb")],
                          truncated={"samples": {"limit": 25}})],
        )
        self.assertEqual(code, 0)
        self.assertEqual(bundle["truncated"], {"samples": {"limit": 25}})

    def test_a_single_endpoint_is_unchanged_by_the_merge_path(self):
        one = _make_bundle([self._ep("/a", "fpa")])
        code, bundle, urls = self._pull(["--endpoint", "GET /a"], [one])
        self.assertEqual(code, 0)
        self.assertEqual(len(urls), 1)
        self.assertEqual(bundle["endpoints"], one["endpoints"])

    def test_no_endpoint_still_pulls_the_whole_project(self):
        code, _, urls = self._pull([], [_make_bundle()])
        self.assertEqual(code, 0)
        self.assertEqual(len(urls), 1)
        self.assertNotIn("method=", urls[0])

    def test_one_malformed_endpoint_fails_before_any_request(self):
        with patch("sys.stderr", new_callable=io.StringIO) as err:
            with patch.dict(os.environ, {"STUBSMITH_API_KEY": "sk-test"}):
                with patch("urllib.request.urlopen") as mopen:
                    code = main(["pull", "--endpoint", "GET /a", "--endpoint", "/b"])
        self.assertEqual(code, 1)
        self.assertIn("--endpoint", err.getvalue())
        mopen.assert_not_called()
