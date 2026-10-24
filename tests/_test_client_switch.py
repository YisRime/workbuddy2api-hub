# -*- coding: utf-8 -*-
"""桌面客户端切号：会话构造、加密回读、备份与失败回滚。

    python tests/_test_client_switch.py

不碰真实客户端：所有文件操作都在临时目录，进程停/启全部 mock。真机切换
（停客户端 -> 写 .info -> explorer 重启）由人工冒烟覆盖，见 README。
"""
import base64
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import wb_client_switch as S  # noqa: E402


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_jwt(uid, exp=None, scope="openid profile offline_access email"):
    header = b64url(b'{"alg":"none","typ":"JWT"}')
    payload = b64url(json.dumps({
        "sub": uid, "exp": int(exp or time.time() + 3600), "scope": scope,
    }).encode("utf-8"))
    return "%s.%s.sig" % (header, payload)


def make_account(uid="u-target", realm="intl"):
    return SimpleNamespace(
        uid=uid,
        realm=realm,
        nickname="Target",
        domain="www.workbuddy.ai",
        access_token=make_jwt(uid),
        refresh_token=make_jwt(uid, time.time() + 7200),
        expires_at=int(time.time() + 3600),
        proxy="",
        is_api_key=False,
    )


def make_profiles(uid="u-target", nickname="Target"):
    return [{
        "uid": uid, "nickname": nickname, "uin": "123456", "type": "personal",
        "lastLogin": True, "pluginEnabled": True,
        "deployStatus": {"statusCode": 0, "statusMsg": "", "detailMsg": ""},
        "accountType": "", "sso": {"domain": "", "domainModifiedTimes": 0},
        "oneidAccountId": "", "isCurrentOneIdEnterprise": False,
    }]


def make_template(uid="u-old"):
    return {
        "account": {
            "uid": uid, "nickname": "Old", "uin": "999", "type": "personal",
            "lastLogin": True, "pluginEnabled": True, "areaInfoComplete": True,
            "isCreator": False, "isAdmin": False, "isFirstLogin": False,
            "logOutEnable": False, "isCurrentOneIdEnterprise": False,
            "isCurrentOneIdPersonal": False, "deployStatus": {}, "accountType": "",
            "sso": {}, "oneidAccountId": "", "idp": "",
        },
        "auth": {
            "accessToken": "old-access", "refreshToken": "old-refresh",
            "expiresIn": 1, "refreshExpiresIn": 1, "tokenType": "Bearer",
            "sessionState": "old-session", "scope": "openid",
            "domain": "www.workbuddy.ai", "lastRefreshTime": 1,
            "expiresAt": 2, "refreshExpiresAt": 2,
        },
        "accounts": [{"uid": uid, "nickname": "Old"}],
        "allAccounts": [{"uid": uid, "nickname": "Old"}],
    }


class QuietSubprocessTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows console windows only")
    def test_tasklist_is_started_without_a_console_window(self):
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(S.subprocess, "run", return_value=completed) as run:
            S._run_quiet(["tasklist"])
        kwargs = run.call_args.kwargs
        self.assertTrue(kwargs.get("creationflags", 0) & 0x08000000)
        self.assertIn("startupinfo", kwargs)


class BuildSessionTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.account = make_account()
        self.template = make_template()

    def test_round_trip_and_encryption(self):
        doc = S.build_session(self.account, self.template, self.key, make_profiles())
        summary = S.session_summary(doc, self.key)
        self.assertEqual(summary["uid"], self.account.uid)
        self.assertEqual(summary["nickname"], "Target")
        self.assertEqual(summary["uin"], "123456")
        self.assertGreater(summary["expiresAt"], int(time.time() * 1000))
        self.assertEqual(doc["account"]["uid"], self.account.uid)
        self.assertEqual(len(doc["accounts"]), 1)
        self.assertEqual(len(doc["allAccounts"]), 1)
        text = json.dumps(doc, ensure_ascii=False)
        self.assertNotIn(self.account.access_token, text)
        self.assertNotIn(self.account.refresh_token, text)
        self.assertIsInstance(doc["account"]["nickname"], dict)
        self.assertIsInstance(doc["auth"]["accessToken"], dict)
        self.assertEqual(doc["auth"]["domain"], "www.workbuddy.ai")

    def test_uid_mismatch_rejected(self):
        account = make_account(uid="u-target")
        account.access_token = make_jwt("u-other")
        with self.assertRaises(S.ClientSwitchError):
            S.build_session(account, self.template, self.key, make_profiles())

    def test_api_key_rejected(self):
        account = make_account()
        account.is_api_key = True
        with self.assertRaises(S.ClientSwitchError):
            S.build_session(account, self.template, self.key, make_profiles())

    def test_missing_profile_rejected(self):
        with self.assertRaises(S.ClientSwitchError):
            S.build_session(self.account, self.template, self.key, make_profiles("u-other"))


class AuthSelectionTests(unittest.TestCase):
    def test_prefers_latest_and_skips_logged_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            intl = os.path.join(tmp, "workbuddy-desktop-ai.info")
            cn = os.path.join(tmp, "workbuddy-desktop.info")
            for path in (intl, cn):
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("{}")
            os.utime(intl, (time.time() - 100, time.time() - 100))
            os.utime(cn, (time.time(), time.time()))
            open(cn + ".logged-out", "w").close()
            with mock.patch.object(S.wb_accounts, "desktop_credential_candidates",
                                   return_value=[(intl, "intl"), (cn, "cn")]):
                path, realm = S.desktop_auth()
            self.assertEqual(path, intl)
            self.assertEqual(realm, "intl")

    def test_no_files_is_actionable(self):
        with mock.patch.object(S.wb_accounts, "desktop_credential_candidates", return_value=[]):
            with self.assertRaises(S.ClientSwitchError) as ctx:
                S.desktop_auth()
            self.assertIn("没有找到", str(ctx.exception))


class BackupTests(unittest.TestCase):
    def test_copies_file_marker_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = os.path.join(tmp, "workbuddy-desktop-ai.info")
            with open(auth, "w", encoding="utf-8") as fh:
                json.dump(make_template(), fh)
            open(auth + ".logged-out", "w").close()
            accounts = os.path.join(tmp, "accounts")
            backup, digest = S.backup_auth(auth, accounts, note="test")
            self.assertTrue(os.path.isfile(os.path.join(backup, os.path.basename(auth))))
            self.assertTrue(os.path.isfile(os.path.join(backup, os.path.basename(auth) + ".logged-out")))
            with open(os.path.join(backup, "manifest.json"), encoding="utf-8") as fh:
                manifest = json.load(fh)
            self.assertEqual(manifest["sha256"], digest)
            self.assertEqual(manifest["note"], "test")


class BackupRetentionTests(unittest.TestCase):
    def test_identical_backup_is_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = os.path.join(tmp, "workbuddy-desktop-ai.info")
            accounts = os.path.join(tmp, "accounts")
            with open(auth, "w", encoding="utf-8") as fh:
                fh.write("same")
            first, _ = S.backup_auth(auth, accounts)
            second, _ = S.backup_auth(auth, accounts)
            self.assertEqual(first, second)
            root = os.path.join(accounts, "agent-backups", "client-auth")
            self.assertEqual(len(os.listdir(root)), 1)

    def test_keeps_only_three_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            auth = os.path.join(tmp, "workbuddy-desktop-ai.info")
            accounts = os.path.join(tmp, "accounts")
            for i in range(6):
                with open(auth, "w", encoding="utf-8") as fh:
                    fh.write("version-%d" % i)
                S.backup_auth(auth, accounts)
            root = os.path.join(accounts, "agent-backups", "client-auth")
            self.assertEqual(len(os.listdir(root)), 3)


class SyncClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.auth = os.path.join(self.tmp.name, "workbuddy-desktop-ai.info")
        with open(self.auth, "w", encoding="utf-8") as fh:
            json.dump(make_template(uid="u-old"), fh)
        self.accounts = os.path.join(self.tmp.name, "accounts")

    def tearDown(self):
        self.tmp.cleanup()

    def test_running_client_is_stopped_and_restarted(self):
        with mock.patch.object(S, "desktop_auth", return_value=(self.auth, "intl")),              mock.patch.object(S, "client_pids", return_value=[1]),              mock.patch.object(S, "stop_client", return_value=[1]) as stop,              mock.patch.object(S, "start_client", return_value=True) as start,              mock.patch.object(S, "sync_local_sessions", return_value={"ok": True, "moved": 5}) as sync:
            out = S.sync_client_sessions(self.accounts)
        self.assertEqual(sync.call_args.args[0], "u-old")
        self.assertTrue(stop.called)
        self.assertTrue(start.called)
        self.assertTrue(out["restarted"])
        self.assertEqual(out["moved"], 5)

    def test_idle_client_only_updates_database(self):
        with mock.patch.object(S, "desktop_auth", return_value=(self.auth, "intl")),              mock.patch.object(S, "client_pids", return_value=[]),              mock.patch.object(S, "stop_client", side_effect=AssertionError("must not stop")),              mock.patch.object(S, "start_client", side_effect=AssertionError("must not start")),              mock.patch.object(S, "sync_local_sessions", return_value={"ok": True, "moved": 3}):
            out = S.sync_client_sessions(self.accounts)
        self.assertFalse(out["restarted"])
        self.assertTrue(out["restartRequired"])


class SessionSyncTests(unittest.TestCase):
    """本地会话列表同步：只搬运有 JSONL 的本地会话，原归属可还原。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.db = os.path.join(self.root, "workbuddy.db")
        os.makedirs(os.path.join(self.root, "projects", "space"), exist_ok=True)
        for sid in ("s1", "s3"):
            with open(os.path.join(self.root, "projects", "space", sid + ".jsonl"), "w",
                      encoding="utf-8") as fh:
                fh.write("{}\n")
        conn = sqlite3.connect(self.db)
        conn.execute("CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT, "
                     "transport TEXT, deleted_at INTEGER)")
        conn.executemany("INSERT INTO sessions VALUES (?,?,?,?)", [
            ("s1", "A", "local", None),
            ("s2", "A", "local", None),
            ("s3", "A", "cloud", None),
            ("s4", "A", "local", 123),
        ])
        conn.commit()
        conn.close()
        self.accounts = os.path.join(self.root, "accounts")

    def tearDown(self):
        self.tmp.cleanup()

    def test_dry_run_counts_without_writing(self):
        out = S.sync_local_sessions("B", self.accounts, db_path=self.db, dry_run=True)
        self.assertEqual(out["eligible"], 1)
        self.assertEqual(out["cloudSkipped"], 1)
        self.assertEqual(out["localWithoutFile"], 1)
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("select user_id from sessions where id='s1'").fetchone()[0], "A")
        conn.close()

    def test_merge_moves_only_local_sessions_with_jsonl(self):
        out = S.sync_local_sessions("B", self.accounts, db_path=self.db)
        self.assertEqual(out["moved"], 1)
        self.assertTrue(os.path.isdir(out["backup"]))
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("select user_id,wb_original_user_id from sessions where id='s1'").fetchone(), ("B", "A"))
        self.assertEqual(conn.execute("select user_id from sessions where id='s2'").fetchone()[0], "A")
        self.assertEqual(conn.execute("select user_id from sessions where id='s3'").fetchone()[0], "A")
        self.assertEqual(conn.execute("select user_id from sessions where id='s4'").fetchone()[0], "A")
        conn.close()

    def test_same_target_again_skips_update_and_backup(self):
        S.sync_local_sessions("B", self.accounts, db_path=self.db)
        out = S.sync_local_sessions("B", self.accounts, db_path=self.db)
        self.assertEqual(out.get("skipped"), "already")
        self.assertEqual(out.get("moved"), 0)

    def test_second_switch_keeps_original_owner(self):
        S.sync_local_sessions("B", self.accounts, db_path=self.db)
        S.sync_local_sessions("C", self.accounts, db_path=self.db)
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("select user_id,wb_original_user_id from sessions where id='s1'").fetchone(), ("C", "A"))
        conn.close()

    def test_restore_puts_everyone_back(self):
        S.sync_local_sessions("B", self.accounts, db_path=self.db)
        out = S.restore_session_owners(self.accounts, db_path=self.db)
        self.assertEqual(out["restored"], 1)
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("select user_id,wb_original_user_id from sessions where id='s1'").fetchone(), ("A", None))
        conn.close()

    def test_missing_db_is_a_noop(self):
        out = S.sync_local_sessions("B", self.accounts, db_path=os.path.join(self.root, "nope.db"))
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("skipped"), "no-db")


class SnapshotTests(unittest.TestCase):
    """独立切号器的单份快照：auth + db 一起备份/恢复，重复备份只留一份。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.auth = os.path.join(self.tmp.name, "workbuddy-desktop-ai.info")
        self.db = os.path.join(self.tmp.name, "workbuddy.db")
        self.backup = os.path.join(self.tmp.name, "Backup")
        with open(self.auth, "w", encoding="utf-8") as fh:
            fh.write("auth-v1")
        with open(self.db, "w", encoding="utf-8") as fh:
            fh.write("db-v1")

    def tearDown(self):
        self.tmp.cleanup()

    def _patched(self):
        return [
            mock.patch.object(S, "desktop_auth", return_value=(self.auth, "intl")),
            mock.patch.object(S, "client_db_path", return_value=self.db),
            mock.patch.object(S, "client_pids", return_value=[]),
            mock.patch.object(S, "start_client", return_value=True),
        ]

    def test_snapshot_and_restore(self):
        patches = self._patched()
        for patch in patches:
            patch.start()
        try:
            out = S.backup_snapshot(self.backup)
            self.assertTrue(os.path.isfile(os.path.join(self.backup, "auth.info")))
            self.assertTrue(os.path.isfile(os.path.join(self.backup, "workbuddy.db")))
            self.assertIn("auth.info", out["files"])
            with open(self.auth, "w", encoding="utf-8") as fh:
                fh.write("auth-v2")
            with open(self.db, "w", encoding="utf-8") as fh:
                fh.write("db-v2")
            S.restore_snapshot(self.backup, restart=False)
            self.assertEqual(open(self.auth, encoding="utf-8").read(), "auth-v1")
            self.assertEqual(open(self.db, encoding="utf-8").read(), "db-v1")
        finally:
            for patch in patches:
                patch.stop()

    def test_second_snapshot_overwrites_the_only_copy(self):
        patches = self._patched()
        for patch in patches:
            patch.start()
        try:
            S.backup_snapshot(self.backup)
            with open(self.auth, "w", encoding="utf-8") as fh:
                fh.write("auth-v2")
            S.backup_snapshot(self.backup)
            self.assertEqual(open(os.path.join(self.backup, "auth.info"), encoding="utf-8").read(), "auth-v2")
            self.assertEqual(len([n for n in os.listdir(self.backup) if n.startswith("auth.info")]), 1)
        finally:
            for patch in patches:
                patch.stop()


class SwitchFlowTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.account = make_account()
        self.template = make_template()
        self.profiles = make_profiles()
        self.tmp = tempfile.TemporaryDirectory()
        self.auth = os.path.join(self.tmp.name, "workbuddy-desktop-ai.info")
        with open(self.auth, "w", encoding="utf-8") as fh:
            json.dump(self.template, fh)

    def tearDown(self):
        self.tmp.cleanup()

    def _common_patches(self):
        return [
            mock.patch.object(S, "desktop_auth", return_value=(self.auth, "intl")),
            mock.patch.object(S.wb_accounts, "desktop_atrest_key", return_value=self.key),
            mock.patch.object(S, "fetch_profiles", return_value=self.profiles),
        ]

    def test_dry_run_stops_at_nothing(self):
        patches = self._common_patches()
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(S, "stop_client", side_effect=AssertionError("must not stop")), \
                 mock.patch.object(S, "start_client", side_effect=AssertionError("must not start")), \
                 mock.patch.object(S, "write_session", side_effect=AssertionError("must not write")), \
                 mock.patch.object(S, "client_pids", return_value=[1]):
                result = S.switch_account(self.account, accounts_dir=self.tmp.name, dry_run=True)
        finally:
            for patch in patches:
                patch.stop()
        self.assertTrue(result["dryRun"])
        self.assertEqual(result["target"]["uid"], self.account.uid)
        self.assertEqual(result["currentUid"], "u-old")

    def test_noop_when_already_target_and_running(self):
        with open(self.auth, "w", encoding="utf-8") as fh:
            json.dump(make_template(uid=self.account.uid), fh)
        patches = self._common_patches()
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(S, "client_pids", return_value=[1]),                  mock.patch.object(S, "stop_client", side_effect=AssertionError("must not stop")),                  mock.patch.object(S, "start_client", side_effect=AssertionError("must not start")),                  mock.patch.object(S, "write_session", side_effect=AssertionError("must not write")):
                result = S.switch_account(self.account, accounts_dir=self.tmp.name)
        finally:
            for patch in patches:
                patch.stop()
        self.assertTrue(result.get("noop"))

    def test_switch_can_sync_sessions_in_the_same_restart(self):
        target_doc = S.build_session(self.account, self.template, self.key, self.profiles)
        patches = self._common_patches()
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(S, "client_pids", return_value=[1]),                  mock.patch.object(S, "read_session", side_effect=[self.template, self.template, target_doc]),                  mock.patch.object(S, "write_session") as write,                  mock.patch.object(S, "stop_client", return_value=[1]),                  mock.patch.object(S, "backup_auth", return_value=(self.tmp.name, "sha")),                  mock.patch.object(S, "start_client", return_value=True),                  mock.patch.object(S, "wait_for_uid", return_value=True),                  mock.patch.object(S, "sync_local_sessions", return_value={"ok": True, "moved": 3}) as sync:
                result = S.switch_account(
                    self.account, accounts_dir=self.tmp.name, sync_sessions=True)
        finally:
            for patch in patches:
                patch.stop()
        self.assertEqual(result["sessions"]["moved"], 3)
        self.assertTrue(write.called)
        self.assertEqual(sync.call_args.args[0], self.account.uid)

    def test_write_failure_restores_backup_and_restarts(self):
        backup_dir = os.path.join(self.tmp.name, "backup")
        os.makedirs(backup_dir)
        shutil_target = os.path.join(backup_dir, os.path.basename(self.auth))
        with open(shutil_target, "w", encoding="utf-8") as fh:
            json.dump(self.template, fh)
        patches = self._common_patches()
        for patch in patches:
            patch.start()
        try:
            with mock.patch.object(S, "client_pids", side_effect=[[1], []]), \
                 mock.patch.object(S, "stop_client", return_value=[1]), \
                 mock.patch.object(S, "backup_auth", return_value=(backup_dir, "sha")), \
                 mock.patch.object(S, "write_session", side_effect=OSError("disk full")), \
                 mock.patch.object(S, "start_client", return_value=True) as start:
                with self.assertRaises(S.ClientSwitchError):
                    S.switch_account(self.account, accounts_dir=self.tmp.name)
                self.assertTrue(start.called)
            with open(self.auth, encoding="utf-8") as fh:
                restored = json.load(fh)
            self.assertEqual(restored["account"]["uid"], "u-old")
        finally:
            for patch in patches:
                patch.stop()


if __name__ == "__main__":
    unittest.main()
