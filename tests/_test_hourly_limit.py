"""每小时 token 节律限速（固定钟点桶，默认关）。"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wb_accounts
import wb_settings


def account(limit=0, uid="u-hour-1"):
    acc = wb_accounts.Account({"uid": uid, "realm": "intl",
                               "domain": "www.workbuddy.ai",
                               "accessToken": "t"})
    acc.hourly_token_limit = limit
    return acc


class HourlyBucketTests(unittest.TestCase):
    def test_accumulates_within_the_hour_and_blocks_at_limit(self):
        acc = account(limit=100)
        self.assertFalse(acc.hourly_limit_blocked())
        acc.note_hourly_usage(60)
        self.assertFalse(acc.hourly_limit_blocked())
        acc.note_hourly_usage(40)
        self.assertTrue(acc.hourly_limit_blocked())
        self.assertFalse(acc.ready())            # 调度跳过该账号

    def test_bucket_rollover_resets(self):
        acc = account(limit=10)
        acc.note_hourly_usage(10)
        self.assertTrue(acc.hourly_limit_blocked())
        # 跨桶：把计数挪到「上一小时」，再记一笔即清掉旧桶。
        with acc._throttle_lock:
            acc._hourly_buckets = {}
        self.assertFalse(acc.hourly_limit_blocked())

    def test_zero_limit_disables_and_bad_input_ignored(self):
        acc = account(limit=0)
        acc.note_hourly_usage(10 ** 9)
        self.assertFalse(acc.hourly_limit_blocked())
        acc.note_hourly_usage(None)
        acc.note_hourly_usage(-5)
        self.assertEqual(acc.hourly_tokens_this_hour(), 10 ** 9)

    def test_ready_stays_true_when_disabled(self):
        acc = account(limit=0)
        acc.note_hourly_usage(12345)
        self.assertTrue(acc.ready())


class HourlySettingsTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="wb-hourly-")

    def test_default_is_off(self):
        self.assertEqual(wb_settings.hourly_token_limit(self.dir), 0)

    def test_round_trip(self):
        wb_settings.set_hourly_token_limit(self.dir, 5000)
        self.assertEqual(wb_settings.hourly_token_limit(self.dir), 5000)

    def test_pool_applies_limits_from_settings(self):
        wb_settings.set_hourly_token_limit(self.dir, 50)
        with open(os.path.join(self.dir, "u-hour-pool.json"), "w",
                  encoding="utf-8") as fh:
            fh.write('{"uid": "u-hour-pool", "realm": "intl", '
                     '"domain": "www.workbuddy.ai", "accessToken": "tok", '
                     '"nickname": "hour"}')
        pool = wb_accounts.AccountPool(self.dir)
        pool.load()
        accs = [a for a in pool.accounts if a.realm == "intl"]
        self.assertTrue(accs)
        pool.apply_daily_token_limit(usage={})
        for acc in accs:
            self.assertEqual(acc.hourly_token_limit, 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
