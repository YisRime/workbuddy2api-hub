"""抓包工具链：脱敏、形状提取、接口面/覆盖分析、反向代理钉位。

Run with: python _test_capture_tools.py
不依赖 mitmproxy（插件里的 mitmproxy 导入是 try/except）。
"""
import contextlib
import gzip
import io
import json
import os
import sys
import tempfile
import types
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_CAPTURE = os.path.join(_ROOT, "tools", "capture")
for _p in (_ROOT, _CAPTURE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import analyze_capture as analyzer
import wb_capture_addon as addon
import wb_reverse_pin as pin


def flow(host, method, path, status, headers, body=b"", ts=0.0):
    rec = addon.build_record(host, method, path, status, headers, body, ts=ts)
    rec["path_tpl"] = addon.path_template(path)
    return rec


class MaskTests(unittest.TestCase):
    def test_bearer_prefix_kept(self):
        self.assertEqual(addon.mask_value("Bearer abcdef"), "Bearer <redacted:13>")

    def test_headers_keep_name_and_order(self):
        out = addon.redact_headers([["Authorization", "Bearer SECRET"],
                                    ["X-IDE-Type", "WorkBuddy"],
                                    ["x-user-id", "u-1"]])
        self.assertEqual([p[0] for p in out], ["Authorization", "X-IDE-Type", "x-user-id"])
        self.assertEqual(out[1][1], "WorkBuddy")
        self.assertNotIn("SECRET", out[0][1])
        self.assertNotIn("u-1", out[2][1])

    def test_body_recursive_redaction(self):
        payload = {"model": "glm-5.2", "metadata": {"machineId": "m-1", "sessionId": "s-1"}}
        out = addon.redact_body(payload)
        self.assertEqual(out["model"], "glm-5.2")
        self.assertNotIn("m-1", json.dumps(out))
        self.assertEqual(payload["metadata"]["machineId"], "m-1")


class ShapeTests(unittest.TestCase):
    def test_path_template(self):
        self.assertEqual(addon.path_template("/v2/c/0f8fad5b-d9cb-469f-a165-70867728950e"),
                         "/v2/c/{uuid}")
        self.assertEqual(addon.path_template("/v2/x/" + "a" * 32), "/v2/x/{hex32}")

    def test_gzip_json(self):
        raw = gzip.compress(json.dumps({"model": "m", "messages": []}).encode())
        info, _ = addon.summarize_body(raw, "application/json")
        self.assertTrue(info["gzip"])
        self.assertEqual(info["keys"], ["messages", "model"])

    def test_sse_summary(self):
        body = b"event: a\ndata: {}\n\nevent: b\ndata: {}\n\n"
        info, _ = addon.summarize_body(body, "text/event-stream")
        self.assertEqual(info["sse_events"], ["a", "b"])
        self.assertEqual(info["sse_data_lines"], 2)

    def test_stream_response_not_read(self):
        rec = addon.build_record("www.workbuddy.ai", "POST", "/v2/chat/completions", 200,
                                 [["content-type", "application/json"]], b"{}",
                                 resp_headers=[["content-type", "text/event-stream"],
                                               ["content-length", "1234"]],
                                 resp_body=None, resp_len=1234)
        self.assertTrue(rec["resp"]["stream"])
        self.assertEqual(rec["resp"]["len"], 1234)


class AnalysisTests(unittest.TestCase):
    def _write(self, records):
        handle = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                             encoding="utf-8")
        with handle:
            for rec in records:
                handle.write(json.dumps(rec) + "\n")
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_surface_groups_by_host(self):
        records = [flow("www.workbuddy.ai", "POST", "/v2/report", 200, []),
                   flow("www.workbuddy.ai", "POST", "/v2/report", 200, []),
                   flow("tencent.sso.codebuddy.cn", "GET", "/api/x", 401, [])]
        flows, fails = analyzer.load(self._write(records))
        text = "\n".join(analyzer.surface(flows, fails))
        self.assertIn("www.workbuddy.ai（2 条 / 1 个接口）", text)
        self.assertIn("`POST /v2/report` | 2 | 200×2", text)

    def test_timeline_orders_by_ts(self):
        records = [flow("www.workbuddy.ai", "POST", "/b", 200, [], ts=200.0),
                   flow("www.workbuddy.ai", "GET", "/a", 200, [], ts=100.0)]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            analyzer.print_timeline(records)
        out = buffer.getvalue()
        self.assertLess(out.index("/a"), out.index("/b"))
        self.assertIn("跨度 100.0s", out)

    def test_coverage_lists_client_only(self):
        lines, client_only, repo_only = analyzer.coverage([])
        self.assertIn("/v2/agentos/localagent/workspaces/websocket", client_only)
        self.assertIn("/v2/plugin/auth/state", repo_only)
        self.assertTrue(any("客户端" in line for line in lines))

    def test_diff_reports_new_path_and_header(self):
        base = [flow("www.workbuddy.ai", "POST", "/v2/chat/completions", 200,
                     [["user-agent", "WorkBuddy/5.8.4"], ["x-old", "1"]])]
        new = base + [flow("www.workbuddy.ai", "POST", "/v2/agentos/x", 200,
                           [["user-agent", "WorkBuddy/5.9.0"], ["x-new", "1"]])]
        text = "\n".join(analyzer.diff(base, new))
        self.assertIn("+ 新接口", text)


class PinTests(unittest.TestCase):
    class _Server(object):
        def __init__(self):
            self.address = ("www.workbuddy.ai", 443)
            self.sni = None

    class _Data(object):
        def __init__(self):
            self.server = PinTests._Server()

    def _addon(self, ip, sni):
        options = types.SimpleNamespace(wb_pin_ip=ip, wb_pin_sni=sni)
        original = pin.ctx
        pin.ctx = types.SimpleNamespace(options=options)
        self.addCleanup(setattr, pin, "ctx", original)
        return pin.ReversePin()

    def test_pins_address_and_sni(self):
        data = self._Data()
        self._addon("43.160.158.125", "www.workbuddy.ai").server_connect(data)
        self.assertEqual(data.server.address, ("43.160.158.125", 443))
        self.assertEqual(data.server.sni, "www.workbuddy.ai")

    def test_requestheaders_restores_host(self):
        class _Req(object):
            def __init__(self):
                self.host = "43.160.158.125"
                self.headers = {"Host": "43.160.158.125"}
        class _Flow(object):
            def __init__(self):
                self.request = _Req()
        f = _Flow()
        self._addon("43.160.158.125", "www.workbuddy.ai").requestheaders(f)
        self.assertEqual(f.request.headers["Host"], "www.workbuddy.ai")
        self.assertEqual(f.request.host, "www.workbuddy.ai")


if __name__ == "__main__":
    unittest.main(verbosity=2)
