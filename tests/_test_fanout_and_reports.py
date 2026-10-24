"""重试扇出上限与对话伴随 /v2/report 事件。"""
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wb_accounts
import wb_identity
import wb_proxy as P
import wb_settings

PAYLOAD = {"model": "test-model",
           "messages": [{"role": "user", "content": "hi"}]}


def http_500():
    return urllib.error.HTTPError("https://upstream/chat", 500, "boom", {},
                                  io.BytesIO(b'{"msg":"boom"}'))


class FakeResp(object):
    status = 200

    def read(self):
        return b""

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class RecordingUpstream(object):
    """每个请求都按类型记录；chat 请求回 500 驱动换号。

    每个账号会先打一次 token 预刷新（失败被上游刷新逻辑吞掉），过滤掉
    只数 chat 出站。
    """

    def __init__(self):
        self.calls = []
        self.chat_calls = []

    def __call__(self, req, timeout=30, proxy=""):
        self.calls.append(req)
        url = str(req.full_url)
        if "/chat/completions" in url:
            self.chat_calls.append(req)
            raise http_500()
        # 刷新/伴随类请求：静默成功。
        return FakeResp()


class StubPool(object):
    def __init__(self, accounts):
        self.accounts = accounts
        self.affinity = wb_accounts.SessionAffinity()

    def apply_remaining_weights(self, weights=None):
        pass

    def count_ready(self, realm, model=None):
        return sum(1 for a in self.accounts if a.ready(model=model))

    def pick_for_session(self, realm=None, session_key=None, exclude=(),
                         model=None, page=None):
        for a in self.accounts:
            if a.uid in exclude or (realm and a.realm != realm):
                continue
            if a.ready(model=model):
                return a
        return None


def _uids_hit(reqs):
    out = []
    for req in reqs:
        uid = req.headers.get("X-user-id")
        if uid not in out:
            out.append(uid)
    return out


class FanoutCapTests(unittest.TestCase):
    def _run(self, accounts, env):
        old_pool, old_urlopen = P.POOL, wb_accounts.urlopen
        upstream = RecordingUpstream()
        P.POOL = StubPool(accounts)
        wb_accounts.urlopen = upstream
        os.environ["WB_FANOUT_MAX"] = env
        raised = None
        try:
            P.open_upstream(dict(PAYLOAD), target_realm="intl")
        except Exception as exc:
            raised = exc
        finally:
            wb_accounts.urlopen = old_urlopen
            P.POOL = old_pool
            os.environ.pop("WB_FANOUT_MAX", None)
        return upstream, raised

    def test_default_caps_fanout_at_two_accounts(self):
        accounts = [wb_accounts.Account({"uid": "f%d" % i,
                                         "accessToken": "t", "realm": "intl"})
                    for i in range(1, 4)]
        upstream, raised = self._run(accounts, "2")
        self.assertIsNotNone(raised)          # 错误交还客户端
        self.assertEqual(len(upstream.chat_calls), 2)
        self.assertEqual(len(_uids_hit(upstream.chat_calls)), 2)

    def test_zero_restores_unlimited_behaviour(self):
        accounts = [wb_accounts.Account({"uid": "g%d" % i,
                                         "accessToken": "t", "realm": "intl"})
                    for i in range(1, 4)]
        upstream, raised = self._run(accounts, "0")
        self.assertIsNotNone(raised)
        self.assertEqual(len(_uids_hit(upstream.chat_calls)), 3)


class ReportChatTurnTests(unittest.TestCase):
    def _account(self, **extra):
        data = {"uid": "u-rep-1", "realm": "intl",
                "domain": "www.workbuddy.ai",
                "accessToken": "tok", "product": "workbuddy"}
        data.update(extra)
        return wb_accounts.Account(data)

    def test_two_events_linked_to_the_wire_ids(self):
        account = self._account()
        calls = []

        def fake_urlopen(req, timeout=30, proxy=""):
            calls.append(req)
            return FakeResp()

        with mock.patch.object(wb_accounts, "urlopen", fake_urlopen):
            ok = account.report_chat_turn(
                conversation_id="conv-1", request_id="req-1",
                message_id="msg-1", trace_id="tr-1",
                root_request_id="root-1", model="m-1",
                messages=3, input_length=42, temperature=0)
        self.assertTrue(ok)
        req = calls[0]
        self.assertTrue(req.full_url.endswith("/v2/report"))
        self.assertEqual(req.headers.get("X-requested-with"), "XMLHttpRequest")
        self.assertEqual(req.headers.get("User-agent"),
                         "WorkBuddy/5.8.4 workbuddy-ai/5.8.4 CLI/2.161.0")
        events = json.loads(req.data.decode("utf-8"))
        self.assertEqual([e["eventCode"] for e in events],
                         ["chat_message_send", "chat_request_send"])
        first, second = events
        self.assertEqual(first["conversationId"], "conv-1")
        self.assertEqual(first["requestId"], "req-1")
        self.assertEqual(first["messageId"], "msg-1")
        self.assertEqual(first["traceId"], "tr-1")
        self.assertEqual(first["rootRequestId"], "root-1")
        self.assertEqual(first["historyCount"], 1)
        self.assertEqual(second["mode"], "craft")
        self.assertEqual(second["inputLength"], 42)
        self.assertEqual(second["temperature"], 0)

    def test_settings_can_disable_and_missing_model_is_a_noop(self):
        directory = tempfile.mkdtemp(prefix="wb-report-off-")
        with open(os.path.join(directory, "settings.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"chat_reports": False}, fh)
        account = self._account()
        account.path = os.path.join(directory, "u.json")
        calls = []

        def fake_urlopen(req, timeout=30, proxy=""):
            calls.append(req)
            return FakeResp()

        with mock.patch.object(wb_accounts, "urlopen", fake_urlopen):
            self.assertFalse(account.report_chat_turn(
                conversation_id="c", request_id="r", message_id="m",
                trace_id="t", model="m-1"))
        self.assertEqual(calls, [])
        # 没带 model 同样不发（open_upstream 不会构造这种调用）。
        self.assertFalse(self._account().report_chat_turn())


class CompanionThreadTests(unittest.TestCase):
    def test_both_companions_run_and_errors_are_swallowed(self):
        account = wb_accounts.Account({"uid": "u-comp", "realm": "intl",
                                       "accessToken": "t",
                                       "product": "workbuddy"})
        touched, reported = [], []

        def fake_touch(session_key, title=None):
            touched.append((session_key, title))

        def fake_report(**kw):
            reported.append(kw)
            raise RuntimeError("telemetry down")   # 失败也必须吞掉

        with mock.patch.object(account, "touch_cloud_conversation", fake_touch), \
                mock.patch.object(account, "report_chat_turn", fake_report):
            P._bg_turn_companions(account, ("sess-1", "标题"), {"model": "m"})
        self.assertEqual(touched, [("sess-1", "标题")])
        self.assertEqual(reported, [{"model": "m"}])

    def test_none_contexts_are_safe(self):
        P._bg_turn_companions(self._any_account(), None, None)  # 不抛即过

    @staticmethod
    def _any_account():
        return wb_accounts.Account({"uid": "u-comp2", "realm": "intl",
                                    "accessToken": "t"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
