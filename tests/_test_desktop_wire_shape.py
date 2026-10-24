"""桌面身份出站头集合 vs 2026-10-24 实测 wire 逐头钉住。

证据基线（mitmproxy local 模式，国际版桌面 5.8.4，capture/lifecycle.jsonl）：
  - chat   :727  POST www.workbuddy.ai/v2/chat/completions（X-Agent-Purpose:
             conversation，OpenAI SDK 形态，43 头含传输层）
  - refresh:711  POST /v2/plugin/auth/token/refresh（桌面主组件，15 头）
  - billing:715  POST /billing/meter/get-user-resource-summary（axios，12 头）

HTTP/1.1 的头名大小写在 wire 上可见，所以这里按**大小写敏感**比较：
官方头名除 x-stainless-* / x-codebuddy-request / acp-connection-id /
traceparent / b3 小写外都是 Title-Case。hub 可控头的集合必须 ⊆ 实测集合
（Content-Encoding 由 open_upstream / probe 在传输层补，不在 headers() 里）；
国内版无实测样本，不在本文件钉。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wb_accounts
import wb_identity

# cap:727 的 43 个头名（原样大小写，含传输层自动头）。
CHAT_WIRE = {
    "Accept", "Content-Type", "X-Requested-With",
    "x-stainless-arch", "x-stainless-lang", "x-stainless-os",
    "x-stainless-package-version", "x-stainless-retry-count",
    "x-stainless-runtime", "x-stainless-runtime-version",
    "X-Conversation-ID", "X-Agent-Intent", "X-Agent-Purpose",
    "X-IDE-Type", "X-IDE-Name", "X-IDE-Version", "X-Private-Data",
    "acp-connection-id", "x-codebuddy-request", "X-Device-Token",
    "X-Request-ID", "X-Conversation-Message-ID",
    "X-Conversation-Request-ID", "X-Root-Request-ID", "X-Agent-Type",
    "Content-Encoding", "traceparent", "b3", "X-B3-TraceId",
    "X-B3-ParentSpanId", "X-B3-SpanId", "X-B3-Sampled", "X-Trace-ID",
    "X-Product", "User-Agent", "Authorization", "X-User-Id", "X-Domain",
    "Content-Length", "Accept-Encoding", "Host", "Connection",
}
# cap:711 的 15 头去掉传输层 3 头（Content-Length/Host/Connection）；
# Accept-Encoding 已由解压层对齐（gzip, deflate），计入 hub 集合。
REFRESH_WIRE = {
    "Accept", "Content-Type", "X-Requested-With", "X-Domain",
    "X-Refresh-Token", "X-Auth-Refresh-Source", "X-Request-ID",
    "X-Product", "User-Agent", "Authorization", "X-User-Id",
    "Accept-Encoding",
}
# cap:715 的 12 头去掉传输层 3 头；Accept-Encoding 同上。
BILLING_WIRE = {
    "Accept", "Content-Type", "Authorization", "X-User-Id", "X-Domain",
    "Accept-Language", "X-Request-ID", "User-Agent", "Accept-Encoding",
}
# 独立 CLI 2.174.0 实测（capture/cli.jsonl，www.codebuddy.ai /v2/chat/completions
# 401'd but fully assembled；去掉传输层与 Authorization/X-User-Id 的值后）。
CLI_WIRE = {
    "Accept", "Content-Type", "x-requested-with",
    "x-stainless-arch", "x-stainless-lang", "x-stainless-os",
    "x-stainless-package-version", "x-stainless-retry-count",
    "x-stainless-runtime", "x-stainless-runtime-version",
    "X-Conversation-ID", "X-Agent-Purpose", "X-IDE-Type", "X-IDE-Name",
    "X-IDE-Version", "X-Agent-Intent", "X-Agent-Runtime",
    "X-Private-Data", "x-codebuddy-request", "X-Request-ID",
    "X-Conversation-Message-ID", "X-Conversation-Request-ID",
    "X-Root-Request-ID", "X-Agent-Type", "baggage", "Content-Encoding",
    "traceparent", "b3", "X-B3-TraceId", "X-B3-ParentSpanId",
    "X-B3-SpanId", "X-B3-Sampled", "X-Trace-ID", "Authorization",
    "X-User-Id", "X-Domain", "X-Product", "User-Agent", "Content-Length",
    "Accept-Encoding", "Host", "Connection",
}


def intl_account(**extra):
    data = {"uid": "u-wire-1", "domain": "www.workbuddy.ai", "realm": "intl",
            "accessToken": "tok", "refreshToken": "rtok"}
    data.update(extra)
    return wb_accounts.Account(data)


class DesktopChatShapeTests(unittest.TestCase):
    def test_header_names_are_subset_of_measured_wire(self):
        headers = intl_account(product="workbuddy").headers(
            purpose="chat", session_key="sess-1")
        extra = set(headers) - CHAT_WIRE
        self.assertEqual(extra, set(), "hub 多发了实测里没有的头: %s" % sorted(extra))

    def test_browser_headers_are_gone_but_sdk_shape_is_kept(self):
        headers = intl_account(product="workbuddy").headers(
            purpose="chat", session_key="sess-1")
        for gone in ("Origin", "Referer", "Accept-Language", "X-CodeBuddy-Request"):
            self.assertNotIn(gone, headers)
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(headers["X-Requested-With"], "XMLHttpRequest")
        self.assertEqual(headers["x-codebuddy-request"], "1")
        # SDK 指纹：7 个 x-stainless-*，没有独立 CLI 才有的 timeout。
        stainless = {k for k in headers if k.startswith("x-stainless-")}
        self.assertEqual(stainless, {
            "x-stainless-arch", "x-stainless-lang", "x-stainless-os",
            "x-stainless-package-version", "x-stainless-retry-count",
            "x-stainless-runtime", "x-stainless-runtime-version"})
        self.assertEqual(headers["x-stainless-runtime-version"], "v22.21.1")
        # main 请求的 b3 四段 + 父 span（cap:727）。
        self.assertIn(headers["X-B3-ParentSpanId"], headers["b3"])
        self.assertTrue(headers["b3"].endswith(
            "-" + headers["X-B3-ParentSpanId"]))

    def test_acp_connection_id_is_stable_per_session(self):
        account = intl_account(product="workbuddy")
        first = account.headers(purpose="chat", session_key="sess-1")
        again = account.headers(purpose="chat", session_key="sess-1")
        other = account.headers(purpose="chat", session_key="sess-2")
        self.assertTrue(first["acp-connection-id"])
        self.assertEqual(first["acp-connection-id"], again["acp-connection-id"])
        self.assertNotEqual(first["acp-connection-id"], other["acp-connection-id"])
        other_account = intl_account(product="workbuddy", uid="u-wire-2")
        self.assertNotEqual(
            first["acp-connection-id"],
            other_account.headers(purpose="chat",
                                  session_key="sess-1")["acp-connection-id"])

    def test_vscode_follows_the_measured_412_wire(self):
        headers = intl_account(product="vscode").headers(purpose="chat")
        # 4.12.39997873 鉴权后 wire 实测（capture/vscode-chat.jsonl:120）：
        # charset Content-Type、无显式 Accept（undici */*）、实例层四头都在、
        # 设备头只有 error 占位（19 字符 sdk_not_initialized）。
        self.assertEqual(headers["Accept"], "*/*")
        self.assertEqual(headers["User-Agent"],
                         "VSCode/1.118.1 CodeBuddy/4.12.39997873")
        self.assertEqual(headers["X-Product"], "SaaS")
        self.assertEqual(headers["X-Product-Version"], "4.12.39997873")
        self.assertEqual(headers["X-Env-ID"], "production")
        self.assertNotIn("Origin", headers)
        self.assertNotIn("x-codebuddy-request", headers)
        self.assertNotIn("acp-connection-id", headers)


class RefreshShapeTests(unittest.TestCase):
    def test_intl_refresh_matches_measured_set(self):
        account = intl_account()
        headers = account._refresh_headers()
        self.assertEqual(set(headers), REFRESH_WIRE,
                         "got %s" % sorted(headers))
        self.assertEqual(headers["User-Agent"], wb_identity.DESKTOP_UA_INTL)
        self.assertEqual(headers["X-Auth-Refresh-Source"], "plugin")
        self.assertNotIn("Origin", headers)


class BillingShapeTests(unittest.TestCase):
    def test_intl_billing_matches_measured_set(self):
        account = intl_account()
        headers = account.headers(purpose="billing")
        # X-No-Enterprise-Id 只在国内版原路径上;国际版实测没有。
        self.assertEqual(set(headers), BILLING_WIRE,
                         "got %s" % sorted(headers))
        self.assertEqual(headers["User-Agent"], "axios/1.16.1")
        self.assertEqual(headers["Accept"], "application/json")


class CliShapeTests(unittest.TestCase):
    """独立 CLI 2.174.0 的 wire（capture/cli.jsonl 实测）逐头钉住。"""

    def test_header_names_match_measured_wire(self):
        account = intl_account(product="cli")
        headers = account.headers(purpose="chat", session_key="sess-1")
        extra = set(headers) - CLI_WIRE
        self.assertEqual(extra, set(), "hub 多发了实测里没有的头: %s" % sorted(extra))

    def test_new_measured_headers_and_omissions(self):
        account = intl_account(product="cli")
        headers = account.headers(purpose="chat", session_key="sess-1")
        self.assertEqual(headers["x-requested-with"], "XMLHttpRequest")
        self.assertEqual(headers["x-codebuddy-request"], "1")
        # baggage：session_id = 会话 id，conversation_request_id = 轮 id。
        self.assertIn("codebuddy.session_id=%s," % headers["X-Conversation-ID"],
                      headers["baggage"])
        self.assertIn(headers["X-Conversation-Request-ID"],
                      headers["baggage"])
        # 官方 CLI 不发 x-stainless-timeout / X-Device-Token；
        # X-Domain 鉴权后带（值 = endpoint 域，capture/cli.jsonl:73）。
        self.assertNotIn("x-stainless-timeout", headers)
        self.assertEqual(headers["X-Domain"], "www.workbuddy.ai")
        self.assertNotIn("X-Device-Token", headers)
        self.assertEqual(headers["User-Agent"], "CLI/2.174.0 CodeBuddy/2.174.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
