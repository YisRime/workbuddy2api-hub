"""桌面身份云端会话生命周期(cap:686-736 实测形态)与云控开关的钉住测试。"""
import json
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wb_accounts
import wb_proxy
import wb_identity


def desktop_account(uid="u-conv-1", nickname="tester"):
    return wb_accounts.Account({
        "uid": uid, "realm": "intl", "domain": "www.workbuddy.ai",
        "accessToken": "tok", "product": "workbuddy", "nickname": nickname,
    })


class FakeResp(object):
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Recorder(object):
    def __init__(self, responses):
        self.calls = []
        self.responses = list(responses)

    def __call__(self, req, timeout=30, proxy=""):
        self.calls.append(req)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return FakeResp(item)


def body_of(req):
    return json.loads(req.data.decode("utf-8"))


def headers_of(req):
    return {k: v for k, v in req.header_items()}


class CloudConversationTests(unittest.TestCase):
    def setUp(self):
        self.account = desktop_account()

    def test_create_follows_measured_body_and_headers(self):
        rec = Recorder([{"code": 0, "data": {"id": "conv-uuid-1"}},
                        {"code": 0}])
        with mock.patch.object(wb_accounts, "urlopen", rec):
            conv = self.account.cloud_conversation("sess-1", "你好，请介绍一下你自己")
        self.assertEqual(conv, "conv-uuid-1")
        create, patch = rec.calls[0], rec.calls[1]
        self.assertTrue(create.full_url.endswith("/console/as/conversations/v2"))
        body = body_of(create)
        self.assertEqual(body["type"], "local")
        self.assertEqual(body["conversationOrigin"], "legacy_workbuddy_local")
        self.assertEqual(body["isPlayground"], 1)
        self.assertEqual(body["name"], "你好，请介绍一下你自己")
        self.assertIn("C:/Users/tester/WorkBuddy AI/", body["workDir"])
        ctx = body["clientContext"]
        self.assertEqual(ctx["localStatus"], "active")
        self.assertEqual(ctx["sessionKind"], "manual")
        # hostId 按账号派生：跨账号不能共用（那是最直接的关联键）。
        other = desktop_account(uid="u-conv-2")
        rec2 = Recorder([{"code": 0, "data": {"id": "x"}}, {"code": 0}])
        with mock.patch.object(wb_accounts, "urlopen", rec2):
            other.cloud_conversation("sess-1", "hi")
        self.assertNotEqual(
            ctx["hostId"], body_of(rec2.calls[0])["clientContext"]["hostId"])
        headers = headers_of(create)
        self.assertEqual(headers["User-agent"],
                         "workbuddy-ai/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0")
        self.assertNotIn("Origin", headers)
        self.assertNotIn("Referer", headers)
        self.assertEqual(headers["X-product"], "SaaS")
        # 创建后紧跟的 isPlayground PATCH（cap:692）。
        self.assertTrue(patch.full_url.endswith("/conversations/conv-uuid-1"))
        self.assertEqual(body_of(patch),
                         {"isPlayground": 1, "updatedAtMs": body["updatedAtMs"]})

    def test_create_is_cached_per_session_key(self):
        rec = Recorder([{"code": 0, "data": {"id": "conv-uuid-1"}},
                        {"code": 0}])
        with mock.patch.object(wb_accounts, "urlopen", rec):
            first = self.account.cloud_conversation("sess-1", "hi")
            again = self.account.cloud_conversation("sess-1", "hi again")
        self.assertEqual(first, again)
        self.assertEqual(len(rec.calls), 2)   # 没有第二次 create

    def test_failure_falls_back_and_cools_down(self):
        real_ttl = wb_accounts.CLOUD_CONV_FAIL_TTL
        wb_accounts.CLOUD_CONV_FAIL_TTL = 0.05
        try:
            rec = Recorder([RuntimeError("boom")])
            with mock.patch.object(wb_accounts, "urlopen", rec):
                self.assertEqual(self.account.cloud_conversation("sess-1", "hi"), "")
                # 冷却期内不重试。
                self.assertEqual(self.account.cloud_conversation("sess-1", "hi"), "")
            self.assertEqual(len(rec.calls), 1)
            time.sleep(0.06)
            rec2 = Recorder([{"code": 0, "data": {"id": "conv-uuid-2"}},
                             {"code": 0}])
            with mock.patch.object(wb_accounts, "urlopen", rec2):
                self.assertEqual(self.account.cloud_conversation("sess-1", "hi"),
                                 "conv-uuid-2")
        finally:
            wb_accounts.CLOUD_CONV_FAIL_TTL = real_ttl

    def test_non_desktop_identity_never_creates(self):
        for product in ("cli", "vscode"):
            account = wb_accounts.Account({
                "uid": "u-conv-9", "realm": "intl", "domain": "www.workbuddy.ai",
                "accessToken": "tok", "product": product})
            rec = Recorder([])
            with mock.patch.object(wb_accounts, "urlopen", rec):
                self.assertEqual(account.cloud_conversation("sess-1", "hi"), "")
            self.assertEqual(len(rec.calls), 0)

    def test_touch_sends_title_once_then_activity(self):
        rec = Recorder([{"code": 0, "data": {"id": "conv-uuid-1"}}, {"code": 0}])
        with mock.patch.object(wb_accounts, "urlopen", rec):
            self.account.cloud_conversation("sess-1", "第一条消息")
        with mock.patch.object(wb_accounts, "urlopen", rec):
            self.account.touch_cloud_conversation("sess-1", title="第一条消息")
            self.account.touch_cloud_conversation("sess-1")
        title_patch, activity_patch = body_of(rec.calls[-2]), body_of(rec.calls[-1])
        self.assertEqual(title_patch["title"], "第一条消息")
        self.assertEqual(title_patch["updatedAtMs"], body_of(rec.calls[0])["createdAtMs"])
        self.assertIn("lastActivityAtMs", activity_patch)
        self.assertNotIn("title", activity_patch)
        # updatedAtMs 冻结在创建时刻（cap:701/731）。
        self.assertEqual(activity_patch["updatedAtMs"], title_patch["updatedAtMs"])


class ProductFeatureTests(unittest.TestCase):
    def tearDown(self):
        wb_identity.set_product_features({"RequestBodyGzip": True})

    def test_flag_roundtrip_and_unknown_payload_keeps_state(self):
        wb_identity.set_product_features({"RequestBodyGzip": False})
        self.assertFalse(wb_identity.product_feature("RequestBodyGzip"))
        # 响应里没有这一节时不改当前值。
        wb_identity.set_product_features({})
        self.assertFalse(wb_identity.product_feature("RequestBodyGzip"))
        wb_identity.set_product_features({"RequestBodyGzip": True})
        self.assertTrue(wb_identity.product_feature("RequestBodyGzip"))
        # 非 dict 载荷（异常响应）直接忽略。
        wb_identity.set_product_features(None)
        self.assertTrue(wb_identity.product_feature("RequestBodyGzip"))


class OpenUpstreamWiringTests(unittest.TestCase):
    """open_upstream 的会话 id 选择接线：云端优先、失败回落、异常不外泄。"""

    def test_cloud_id_wins_and_touch_is_prepared(self):
        account = desktop_account()
        with mock.patch.object(
                wb_accounts.Account, "cloud_conversation",
                return_value="cloud-uuid") as cloud:
            conv, touch = wb_proxy._desktop_conv_lifecycle(
                account, "sess-1",
                {"messages": [{"role": "user", "content": "你好"}]})
        self.assertEqual(conv, "cloud-uuid")
        self.assertEqual(touch, ("sess-1", "你好"))
        cloud.assert_called_once()

    def test_failure_falls_back_to_derived_id_without_touch(self):
        account = desktop_account()
        with mock.patch.object(
                wb_accounts.Account, "cloud_conversation",
                side_effect=RuntimeError("net down")):
            conv, touch = wb_proxy._desktop_conv_lifecycle(
                account, "sess-1", {"messages": []})
        self.assertTrue(conv)          # 回落派生 id
        self.assertNotEqual(conv, "")
        self.assertIsNone(touch)

    def test_vscode_identity_skips_the_lifecycle(self):
        account = wb_accounts.Account({
            "uid": "u-conv-v", "realm": "intl", "domain": "www.workbuddy.ai",
            "accessToken": "t", "product": "vscode"})
        with mock.patch.object(
                wb_accounts.Account, "cloud_conversation",
                return_value="cloud-uuid") as cloud:
            conv, touch = wb_proxy._desktop_conv_lifecycle(
                account, "sess-1", {"messages": []})
        cloud.assert_not_called()
        self.assertIsNone(touch)


if __name__ == "__main__":
    unittest.main(verbosity=2)
