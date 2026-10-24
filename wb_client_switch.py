# -*- coding: utf-8 -*-
"""把账号池里的一个账号切换成桌面客户端当前登录的账号。

为什么需要这个模块：桌面客户端只保存一份登录态（auth/<id>.info），没有
「多账号切换」UI。账号池里已经有 accessToken / refreshToken，把目标账号的
会话写进这份文件、重启客户端，就能在不重新扫码的情况下换号。

链路（2026-10-23 真机验证，WorkBuddy 5.8.4 / Windows）：

    POST /v2/plugin/auth/state?platform=workbuddy-ai
      -> {state, authUrl};  authUrl = /login?platform=workbuddy-ai&state=...
    浏览器登录成功
      -> GET /v2/plugin/auth/token?state=... （1s 轮询，pending code 11217）
      -> {accessToken, refreshToken, expiresAt, domain}
      -> 客户端把整份会话写到 auth/workbuddy-desktop-ai.info

本模块走的是最后一步：读当前 .info 作为字段模板，用 /v2/accounts 补齐
uid/nickname/uin 等档案字段，用 wb_atrest.seal() 把 token/nickname 重新
封成 $wbEncrypted，原子替换文件，然后停/启客户端。

安全边界：
* 只操作本机桌面客户端的登录态文件；不碰上游、不改 token 的归属；
* 写前一定备份（accounts/agent-backups/client-auth/<timestamp>/）；
* 写后回读校验；启动失败或校验不过会回滚到备份并重新拉起客户端；
* 默认只允许回环地址调用（由 wb_proxy 的 peer_is_loopback 判定）。
"""
import base64
import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import uuid

import wb_accounts
import wb_atrest

#: 桌面客户端进程名；国际版 WorkBuddyAI.exe，国内版历史上有 WorkBuddy.exe。
CLIENT_PROCESS_NAMES = ("WorkBuddyAI.exe", "WorkBuddy.exe")
CLIENT_EXE_CANDIDATES = (
    r"%ProgramFiles%\WorkBuddyAI\WorkBuddyAI.exe",
    r"%ProgramFiles%\WorkBuddy\WorkBuddy.exe",
    r"%LOCALAPPDATA%\Programs\WorkBuddyAI\WorkBuddyAI.exe",
    r"%LOCALAPPDATA%\Programs\WorkBuddy\WorkBuddy.exe",
)
#: 登录态文件名（与 wb_accounts.REALM_CONFIGS[*]["info_filename"] 一致）
AUTH_FILENAMES = {
    "intl": "workbuddy-desktop-ai.info",
    "cn": "workbuddy-desktop.info",
}
#: 一次性切换锁：两个请求同时停/启客户端只会互相踩。
_SWITCH_LOCK = threading.Lock()
#: 客户端启动后等待它把 auth 文件读进内存并回写的最长时间。
START_VERIFY_TIMEOUT = 25.0


class ClientSwitchError(RuntimeError):
    """可预期的切换失败（没有客户端、没有登录态、上游档案取不到…）。"""


def _log(log, message):
    if log:
        try:
            log(message)
        except Exception:
            pass


def _now_ms():
    return int(time.time() * 1000)


def _jwt_claims(token):
    try:
        part = str(token or "").split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def _jwt_exp(token):
    try:
        return int(_jwt_claims(token).get("exp") or 0)
    except Exception:
        return 0


# --------------------------------------------------------------- 客户端进程
def _run_quiet(args, timeout=15):
    """跑一个控制台子进程，但不弹窗。

    网关通常由 pythonw / 服务启动，没有自己的控制台；Windows 上每次
    tasklist / taskkill 都会新分配一个控制台窗口。CREATE_NO_WINDOW 是
    抑制它的正解，STARTF_USESHOWWINDOW + SW_HIDE 是给少数不认前者的小
    工具兜底。
    """
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            kwargs["startupinfo"] = startupinfo
        except Exception:
            pass
    try:
        return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False, **kwargs)
    except Exception:
        return None


def _tasklist_rows():
    """当前 WorkBuddy 进程 [(pid, name)]，只认 CLIENT_PROCESS_NAMES。"""
    if os.name != "nt":
        rows = []
        for name in CLIENT_PROCESS_NAMES:
            proc = _run_quiet(["pgrep", "-f", name])
            if proc and proc.returncode == 0:
                for line in proc.stdout.decode("utf-8", "replace").splitlines():
                    try:
                        rows.append((int(line.strip()), name))
                    except ValueError:
                        pass
        return rows
    rows = []
    wanted = {name.lower() for name in CLIENT_PROCESS_NAMES}
    proc = _run_quiet(["tasklist", "/FO", "CSV", "/NH"])
    if proc and proc.returncode == 0:
        text = proc.stdout.decode("utf-8", "replace")
        for row in csv.reader(text.splitlines()):
            if len(row) < 2:
                continue
            name = row[0].strip()
            if name.lower() not in wanted:
                continue
            try:
                rows.append((int(row[1]), name))
            except ValueError:
                pass
    return rows


def client_pids():
    return [pid for pid, _ in _tasklist_rows()]


def _terminate_pid(pid):
    """TerminateProcess 比 taskkill 可靠：客户端的 elevate/辅助进程常拒绝 taskkill。"""
    if os.name != "nt":
        try:
            os.kill(pid, 15)
            return True
        except Exception:
            return False
    try:
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x0001, False, int(pid))  # PROCESS_TERMINATE
        if not handle:
            return False
        try:
            return bool(kernel32.TerminateProcess(handle, 1))
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return False


def stop_client(timeout=15.0, log=None):
    """先礼貌 taskkill，再对残留进程 TerminateProcess。返回被停掉的 PID。"""
    rows = _tasklist_rows()
    if not rows:
        return []
    pids = [pid for pid, _ in rows]
    names = sorted({name for _, name in rows})
    for name in names:
        _run_quiet(["taskkill", "/IM", name], timeout=10)
    # 给托盘/窗口一次正常退出的机会；不要每 200ms 起一个 tasklist，之前那版
    # 一次切号能拉起十几个子进程（也是命令行弹窗的来源之一）。
    time.sleep(2.0)
    for pid, _ in _tasklist_rows():
        _terminate_pid(pid)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _tasklist_rows():
            _log(log, "desktop client stopped (%d process(es))" % len(pids))
            return pids
        time.sleep(0.5)
    left = _tasklist_rows()
    raise ClientSwitchError("无法完全停止 WorkBuddy 客户端（仍有 %d 个进程）" % len(left))


def _parse_exe(command):
    match = re.match(r'\s*"([^"]+\.exe)"', str(command or ""), re.I)
    if match:
        return match.group(1)
    match = re.match(r"\s*(\S+\.exe)", str(command or ""), re.I)
    return match.group(1) if match else ""


def client_exe():
    """客户端可执行文件：WB_CLIENT_EXE > URL scheme 注册表 > 常见安装路径。"""
    env = os.environ.get("WB_CLIENT_EXE")
    if env and os.path.isfile(env):
        return os.path.abspath(env)
    if os.name == "nt":
        try:
            import winreg
            for scheme in ("workbuddy-ai", "workbuddy", "buddy-app"):
                try:
                    with winreg.OpenKey(
                            winreg.HKEY_CURRENT_USER,
                            r"Software\Classes\%s\shell\open\command" % scheme) as key:
                        command = winreg.QueryValueEx(key, "")[0]
                except OSError:
                    continue
                exe = _parse_exe(command)
                if exe and os.path.isfile(exe):
                    return exe
        except Exception:
            pass
    for candidate in CLIENT_EXE_CANDIDATES:
        path = os.path.expandvars(candidate)
        if os.path.isfile(path):
            return path
    return ""


def start_client(timeout=20.0, log=None):
    """启动客户端。

    Windows 上故意用 explorer.exe 代启：网关通常由 pythonw/服务/容器启动，
    直接 Popen 会把客户端挂在网关自己的 job object 下，网关一退出客户端就
    被一起收走；explorer 在用户桌面会话里，代启出来的进程不属于这个 job。
    """
    exe = client_exe()
    if not exe:
        raise ClientSwitchError("找不到 WorkBuddy 客户端可执行文件（可用 WB_CLIENT_EXE 指定）")
    if os.name == "nt":
        _run_quiet(["explorer.exe", exe], timeout=15)
    else:
        try:
            subprocess.Popen([exe], close_fds=True, start_new_session=True)
        except Exception as exc:
            raise ClientSwitchError("启动 WorkBuddy 失败：%s" % exc)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if client_pids():
            _log(log, "desktop client started (%d process(es))" % len(client_pids()))
            return True
        time.sleep(0.5)
    raise ClientSwitchError("已写入登录态，但 WorkBuddy 客户端没有启动起来")


# ------------------------------------------------------------------ 登录态
def desktop_auth():
    """返回 (info 路径, realm)。取最近修改、且没有 logged-out 标记的那份。"""
    pairs = []
    for path, realm in wb_accounts.desktop_credential_candidates():
        if not os.path.isfile(path):
            continue
        if os.path.exists(path + ".logged-out"):
            continue
        pairs.append((path, realm))
    if not pairs:
        markers = []
        for path, realm in wb_accounts.desktop_credential_candidates():
            if os.path.exists(path + ".logged-out"):
                markers.append(path + ".logged-out")
        if markers:
            raise ClientSwitchError(
                "桌面客户端当前是登出状态（找到 %s）；先在客户端登录一次，再切号" % markers[0])
        raise ClientSwitchError("没有找到 WorkBuddy 桌面客户端登录态文件（客户端没登录过？）")
    pairs.sort(key=lambda item: os.path.getmtime(item[0]), reverse=True)
    return pairs[0]


def read_session(path):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:
        raise ClientSwitchError("读取登录态失败：%s" % exc)
    if not isinstance(doc, dict) or not isinstance(doc.get("auth"), dict):
        raise ClientSwitchError("登录态文件结构不认识：%s" % path)
    return doc


def current_client():
    """当前桌面客户端登录账号（不回收密钥，只读 auth 文件）。"""
    path, realm = desktop_auth()
    doc = read_session(path)
    uid = str((doc.get("account") or {}).get("uid") or "")
    return {"uid": uid, "realm": realm, "authPath": path}


def write_session(path, doc):
    """同目录临时文件 + os.replace，避免客户端 watcher 读到半个 JSON。"""
    tmp = "%s.switch-%d.tmp" % (path, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


#: 每类备份最多留三份（用户口径：只保留三份，避免重复与冗余）。
BACKUP_KEEP = 3


def _sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _signature_pairs(pairs):
    """[(name, sha256)] -> 稳定签名；用于判断这次备份与最近一份是否完全相同。"""
    parts = ["%s:%s" % (name, digest) for name, digest in sorted(pairs)]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _manifest_signature(dest):
    try:
        with open(os.path.join(dest, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        pairs = []
        for item in manifest.get("files") or []:
            if isinstance(item, dict):
                name = str(item.get("name") or "")
                digest = str(item.get("sha256") or "")
            else:
                name = str(item or "")
                path = os.path.join(dest, name) if name else ""
                digest = _sha256_file(path) if path and os.path.isfile(path) else ""
            if name and digest:
                pairs.append((name, digest))
        return _signature_pairs(pairs)
    except Exception:
        return ""


def _newest_backup(root):
    try:
        dirs = [os.path.join(root, name) for name in os.listdir(root)
                if os.path.isdir(os.path.join(root, name))]
    except OSError:
        return ""
    if not dirs:
        return ""
    dirs.sort(key=lambda p: (os.path.getmtime(p), os.path.basename(p)), reverse=True)
    return dirs[0]


def _prune_backups(root, keep=BACKUP_KEEP, log=None):
    """按修改时间保留最新 keep 份，并删掉 manifest 签名完全相同的重复份。"""
    try:
        dirs = [os.path.join(root, name) for name in os.listdir(root)
                if os.path.isdir(os.path.join(root, name))]
    except OSError:
        return 0
    dirs.sort(key=lambda p: (os.path.getmtime(p), os.path.basename(p)), reverse=True)
    seen = set()
    kept = 0
    removed = 0
    for dest in dirs:
        signature = _manifest_signature(dest)
        duplicate = bool(signature and signature in seen)
        over_limit = kept >= keep
        if duplicate or over_limit:
            try:
                shutil.rmtree(dest)
                removed += 1
                _log(log, "pruned old backup: %s" % os.path.basename(dest))
            except OSError:
                pass
            continue
        if signature:
            seen.add(signature)
        kept += 1
    return removed


def prune_backups(accounts_dir, keep=BACKUP_KEEP, log=None):
    """手动把两类备份都收缩到 keep 份（切号/同步时也会自动调用）。"""
    root = os.path.join(accounts_dir, "agent-backups")
    return {
        "client-auth": _prune_backups(os.path.join(root, "client-auth"), keep, log),
        "client-db": _prune_backups(os.path.join(root, "client-db"), keep, log),
    }


def backup_auth(path, accounts_dir, note=""):
    """把当前 .info（含 logged-out 标记）备份到 accounts/agent-backups/client-auth。

    与最新一份内容完全相同时直接复用，不再新建目录；每类最多留 BACKUP_KEEP 份。
    """
    root = os.path.join(accounts_dir, "agent-backups", "client-auth")
    marker = path + ".logged-out"
    pairs = [(os.path.basename(path), _sha256_file(path))]
    if os.path.exists(marker):
        pairs.append((os.path.basename(marker), _sha256_file(marker)))
    signature = _signature_pairs(pairs)
    newest = _newest_backup(root)
    if newest and _manifest_signature(newest) == signature:
        with open(os.path.join(newest, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        return newest, str(manifest.get("sha256") or "")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(root, stamp)
    suffix = 1
    while os.path.exists(dest):
        suffix += 1
        dest = os.path.join(root, "%s-%d" % (stamp, suffix))
    os.makedirs(dest, exist_ok=True)
    shutil.copy2(path, os.path.join(dest, os.path.basename(path)))
    files = [{
        "name": os.path.basename(path),
        "bytes": os.path.getsize(path),
        "sha256": pairs[0][1],
    }]
    if os.path.exists(marker):
        shutil.copy2(marker, os.path.join(dest, os.path.basename(marker)))
        files.append({
            "name": os.path.basename(marker),
            "bytes": os.path.getsize(marker),
            "sha256": pairs[1][1],
        })
    digest = pairs[0][1]
    manifest = {
        "created": stamp,
        "note": note,
        "source": path,
        "sha256": digest,
        "files": files,
    }
    with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
    _prune_backups(root)
    return dest, digest


def _retire_logout_marker(path):
    """客户端看到 *.logged-out 会拒绝加载 .info；切号前把它改名留档。"""
    marker = path + ".logged-out"
    if not os.path.exists(marker):
        return ""
    retired = "%s.switch-%s" % (marker, time.strftime("%Y%m%d-%H%M%S"))
    try:
        os.replace(marker, retired)
        return retired
    except OSError as exc:
        raise ClientSwitchError("无法移走登出标记 %s：%s" % (marker, exc))


# ---------------------------------------------------------- 本地会话列表同步
def client_db_path():
    """桌面客户端的会话数据库：<客户端配置目录>/workbuddy.db。"""
    return os.path.join(wb_atrest.config_dir(), "workbuddy.db")


def _local_session_ids(config_dir):
    """projects/**/*.jsonl 里的 session id 集合（只认有消息文件的本地会话）。"""
    root = os.path.join(config_dir, "projects")
    ids = set()
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith(".jsonl"):
                ids.add(name[:-len(".jsonl")])
    return ids


def backup_client_db(accounts_dir, db_path=None):
    """备份会话数据库（db + wal + shm），返回备份目录。

    与最新一份内容完全相同时直接复用；每类最多留 BACKUP_KEEP 份。
    """
    db_path = db_path or client_db_path()
    root = os.path.join(accounts_dir, "agent-backups", "client-db")
    names = [os.path.basename(db_path),
             os.path.basename(db_path) + "-wal",
             os.path.basename(db_path) + "-shm"]
    sources = []
    for name in names:
        src = os.path.join(os.path.dirname(db_path), name)
        if os.path.isfile(src):
            sources.append((name, src, _sha256_file(src)))
    signature = _signature_pairs([(name, digest) for name, _src, digest in sources])
    newest = _newest_backup(root)
    if newest and _manifest_signature(newest) == signature:
        return newest
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(root, stamp)
    suffix = 1
    while os.path.exists(dest):
        suffix += 1
        dest = os.path.join(root, "%s-%d" % (stamp, suffix))
    os.makedirs(dest, exist_ok=True)
    files = []
    for name, src, digest in sources:
        shutil.copy2(src, os.path.join(dest, name))
        files.append({"name": name, "bytes": os.path.getsize(src), "sha256": digest})
    manifest = {"created": stamp, "source": db_path, "files": files}
    with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
    _prune_backups(root)
    return dest


def _clear_directory(path):
    path = os.path.abspath(path)
    if os.path.isdir(path):
        for name in os.listdir(path):
            item = os.path.join(path, name)
            if os.path.isdir(item) and not os.path.islink(item):
                shutil.rmtree(item)
            else:
                try:
                    os.unlink(item)
                except OSError:
                    pass
    else:
        os.makedirs(path, exist_ok=True)
    return path


def backup_snapshot(dest_dir, db_path=None, log=None):
    """把登录态 + 会话数据库合并成一份快照，直接写进 dest_dir。

    独立切号器用：每次操作前清空并重写同一个目录，所以永远只有一份；
    与 hub 的 client-auth/client-db 多份滚动备份互不影响。
    """
    auth_path, realm = desktop_auth()
    db_path = db_path or client_db_path()
    dest = _clear_directory(dest_dir)
    files = []

    def copy(src, name):
        if not os.path.isfile(src):
            return
        shutil.copy2(src, os.path.join(dest, name))
        with open(src, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        files.append({"name": name, "bytes": os.path.getsize(src), "sha256": digest})

    copy(auth_path, "auth.info")
    copy(auth_path + ".logged-out", "auth.info.logged-out")
    copy(db_path, "workbuddy.db")
    copy(db_path + "-wal", "workbuddy.db-wal")
    copy(db_path + "-shm", "workbuddy.db-shm")
    manifest = {
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "authSource": auth_path,
        "dbSource": db_path,
        "realm": realm,
        "files": files,
    }
    with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
    _log(log, "snapshot saved: %s (%d file(s))" % (dest, len(files)))
    return {"ok": True, "path": dest, "authPath": auth_path, "dbPath": db_path,
            "files": [item["name"] for item in files]}


def restore_snapshot(dest_dir, restart=True, start=True, log=None):
    """把 backup_snapshot() 的单份快照恢复到本机客户端。

    恢复前会停客户端；默认恢复后重新启动。缺少 db-wal/shm 时会先删掉目标
    的旧 WAL，避免 SQLite 把旧日志盖回新库。
    """
    dest = os.path.abspath(dest_dir)
    manifest_path = os.path.join(dest, "manifest.json")
    if not os.path.isfile(manifest_path):
        raise ClientSwitchError("没有找到备份快照：%s" % dest)
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    auth_path = str(manifest.get("authSource") or "")
    if not auth_path:
        auth_path, _realm = desktop_auth()
    try:
        current_auth, _realm = desktop_auth()
        if os.path.basename(current_auth) == os.path.basename(auth_path):
            auth_path = current_auth
    except Exception:
        pass
    db_path = str(manifest.get("dbSource") or "") or client_db_path()
    current_db = client_db_path()
    if os.path.basename(current_db) == os.path.basename(db_path):
        db_path = current_db
    if not os.path.isfile(os.path.join(dest, "auth.info")):
        raise ClientSwitchError("备份快照缺少 auth.info：%s" % dest)
    running = bool(client_pids())
    if restart and running:
        stop_client(log=log)
    restored = []
    try:
        marker = auth_path + ".logged-out"
        if os.path.exists(marker):
            os.unlink(marker)
        shutil.copy2(os.path.join(dest, "auth.info"), auth_path)
        restored.append(os.path.basename(auth_path))
        backup_marker = os.path.join(dest, "auth.info.logged-out")
        if os.path.isfile(backup_marker):
            shutil.copy2(backup_marker, marker)
            restored.append(os.path.basename(marker))
        for suffix in ("-wal", "-shm"):
            target = db_path + suffix
            if os.path.exists(target):
                try:
                    os.unlink(target)
                except OSError:
                    pass
        if os.path.isfile(os.path.join(dest, "workbuddy.db")):
            shutil.copy2(os.path.join(dest, "workbuddy.db"), db_path)
            restored.append(os.path.basename(db_path))
            for suffix, name in (("-wal", "workbuddy.db-wal"), ("-shm", "workbuddy.db-shm")):
                src = os.path.join(dest, name)
                if os.path.isfile(src):
                    shutil.copy2(src, db_path + suffix)
                    restored.append(os.path.basename(db_path + suffix))
        started = False
        if restart and start:
            started = start_client(log=log)
        _log(log, "snapshot restored: %s" % ", ".join(restored))
        return {"ok": True, "restored": restored, "authPath": auth_path,
                "dbPath": db_path, "started": started}
    except Exception:
        if restart and running and not client_pids():
            try:
                start_client(log=log)
            except Exception:
                pass
        raise


def _has_column(conn, table, column):
    return column in [row[1] for row in conn.execute("PRAGMA table_info(%s)" % table)]


def sync_local_sessions(target_uid, accounts_dir, db_path=None, dry_run=False, log=None, backup=True):
    """把本机所有「有 JSONL 消息文件」的本地会话并入 target_uid 的列表。

    背景：客户端的会话列表按 sessions.user_id 过滤；账号一切，侧边栏就只剩
    新账号的会话。会话消息本身在 projects/**/<id>.jsonl 里，和账号无关，所以
    把本地会话的 user_id 指到当前账号即可在列表里看到并正常打开（真机实测）。
    云端会话（transport='cloud'）的消息在服务端、按原账号鉴权，不能靠本地
    文件合并，这里刻意不碰。

    原归属写进新增列 wb_original_user_id，可用 restore_session_owners() 还原；
    每次修改前备份 workbuddy.db（含 wal/shm）。
    """
    target_uid = str(target_uid or "").strip()
    if not target_uid:
        raise ClientSwitchError("缺少目标 uid")
    db_path = db_path or client_db_path()
    if not os.path.isfile(db_path):
        return {"ok": True, "skipped": "no-db", "moved": 0, "eligible": 0}
    config_dir = os.path.dirname(db_path)
    local_ids = _local_session_ids(config_dir)
    conn = sqlite3.connect(db_path, timeout=20)
    try:
        rows = conn.execute(
            "SELECT id, user_id FROM sessions "
            "WHERE transport = 'local' AND deleted_at IS NULL").fetchall()
        eligible = [(str(sid), str(uid or "")) for sid, uid in rows if str(sid) in local_ids]
        already = sum(1 for _sid, uid in eligible if uid == target_uid)
        cloud = conn.execute(
            "SELECT count(*) FROM sessions WHERE transport = 'cloud'").fetchone()[0]
        if dry_run:
            return {"ok": True, "dryRun": True, "eligible": len(eligible),
                    "already": already, "cloudSkipped": int(cloud or 0),
                    "localWithoutFile": len(rows) - len(eligible)}
        if eligible and already == len(eligible):
            # 全都已经在目标账号下：不再 UPDATE，也就不必再生成一份相同的库备份。
            return {"ok": True, "moved": 0, "eligible": len(eligible),
                    "already": already, "cloudSkipped": int(cloud or 0),
                    "skipped": "already"}
        dest = backup_client_db(accounts_dir, db_path) if backup else ""
        if not _has_column(conn, "sessions", "wb_original_user_id"):
            conn.execute("ALTER TABLE sessions ADD COLUMN wb_original_user_id TEXT")
        moved = 0
        for sid, uid in eligible:
            conn.execute(
                "UPDATE sessions SET wb_original_user_id = COALESCE(wb_original_user_id, ?), "
                "user_id = ? WHERE id = ?", (uid, target_uid, sid))
            moved += 1
        conn.commit()
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.DatabaseError:
            pass
        _log(log, "local sessions merged into %s: %d (cloud skipped: %s)"
             % (target_uid[:8], moved, cloud))
        return {"ok": True, "moved": moved, "eligible": len(eligible),
                "already": already, "cloudSkipped": int(cloud or 0),
                "backup": dest}
    except sqlite3.DatabaseError as exc:
        raise ClientSwitchError("同步本地会话列表失败：%s" % exc)
    finally:
        conn.close()


def restore_session_owners(accounts_dir, db_path=None, log=None):
    """把 sync_local_sessions() 改过的 user_id 还原成原账号。"""
    db_path = db_path or client_db_path()
    if not os.path.isfile(db_path):
        return {"ok": True, "skipped": "no-db", "restored": 0}
    conn = sqlite3.connect(db_path, timeout=20)
    try:
        if not _has_column(conn, "sessions", "wb_original_user_id"):
            return {"ok": True, "restored": 0}
        dest = backup_client_db(accounts_dir, db_path)
        cur = conn.execute(
            "UPDATE sessions SET user_id = wb_original_user_id, wb_original_user_id = NULL "
            "WHERE wb_original_user_id IS NOT NULL AND wb_original_user_id <> ''")
        conn.commit()
        restored = cur.rowcount if cur.rowcount is not None else 0
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.DatabaseError:
            pass
        _log(log, "restored %d session owner(s)" % restored)
        return {"ok": True, "restored": restored, "backup": dest}
    except sqlite3.DatabaseError as exc:
        raise ClientSwitchError("还原会话归属失败：%s" % exc)
    finally:
        conn.close()


def sync_client_sessions(accounts_dir, uid=None, restart=True, log=None, backup=True):
    """面板「同步会话」入口的并发闸门（与切号共用一把锁）。"""
    if not _SWITCH_LOCK.acquire(False):
        raise ClientSwitchError("已有一个切号或同步操作在进行，请稍后再试")
    try:
        return _sync_client_sessions(accounts_dir, uid=uid, restart=restart, log=log, backup=backup)
    finally:
        _SWITCH_LOCK.release()


def _sync_client_sessions(accounts_dir, uid=None, restart=True, log=None, backup=True):
    """把本地会话合并到当前客户端登录的账号。

    - 不传 uid 时取客户端 auth 文件里的当前登录账号；
    - 客户端在跑时先停、同步完再拉起，否则只改数据库并提示下次启动生效；
    - 不碰云端会话（sync_local_sessions 已按 transport='local' 过滤）。
    """
    path, realm = desktop_auth()
    target_uid = str(uid or "").strip()
    if not target_uid:
        doc = read_session(path)
        target_uid = str((doc.get("account") or {}).get("uid") or "")
    if not target_uid:
        raise ClientSwitchError("读不到桌面客户端当前登录账号")
    running = bool(client_pids())
    if uid and running:
        current = str((read_session(path).get("account") or {}).get("uid") or "")
        if current and current != target_uid:
            raise ClientSwitchError("目标账号与当前客户端登录账号不一致，请先切换客户端")
    if restart and running:
        stop_client(log=log)
    try:
        result = sync_local_sessions(target_uid, accounts_dir, log=log, backup=backup)
    except Exception:
        if restart and running:
            try:
                start_client(log=log)
            except Exception:
                pass
        raise
    restarted = False
    if restart and running:
        start_client(log=log)
        restarted = True
    result.update({
        "ok": True,
        "uid": target_uid,
        "realm": realm,
        "restarted": restarted,
        "restartRequired": not running,
    })
    return result


# ------------------------------------------------------------------ 上游档案
def _account_headers(account):
    cfg = wb_accounts.get_realm_config(account.realm)
    return cfg, {
        "Accept": "application/json, text/plain, */*",
        "Authorization": "Bearer " + str(account.access_token or ""),
        "X-Domain": account.domain or cfg["domain"],
        "User-Agent": cfg["chat_ua"],
        "Origin": cfg["origin"],
        "Referer": cfg["origin"] + "/",
    }


def fetch_profiles(account, log=None):
    """GET /v2/accounts，返回与客户端 session.accounts 同形的档案列表。"""
    cfg, headers = _account_headers(account)
    try:
        payload = wb_accounts.http_json(
            cfg["chat_upstream"] + "/v2/accounts", method="GET", headers=headers,
            timeout=20, retries=2, log=log, proxy=getattr(account, "proxy", ""))
    except Exception as exc:
        raise ClientSwitchError("读取上游账号档案失败：%s" % exc)
    rows = ((payload or {}).get("data") or {}).get("accounts") or []
    if not isinstance(rows, list) or not rows:
        raise ClientSwitchError("上游 /v2/accounts 没有返回账号档案")
    profiles = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("uid"):
            continue
        profiles.append(row)
    if not any(str(row.get("uid")) == account.uid for row in profiles):
        raise ClientSwitchError("上游档案里没有目标账号 %s（token 与账号不匹配？）" % account.uid[:8])
    return profiles


def _merge_profile(template_account, profile, target_uid):
    """把 /v2/accounts 的档案合并进模板，保留模板里客户端独有的字段。"""
    base = dict(template_account or {})
    for key in ("uid", "uin", "type", "lastLogin", "pluginEnabled", "deployStatus",
                "accountType", "sso", "oneidAccountId", "isCurrentOneIdEnterprise",
                "isCurrentOneIdPersonal"):
        if key in profile:
            base[key] = profile[key]
    base["uid"] = str(profile.get("uid") or "")
    base["lastLogin"] = base["uid"] == str(target_uid)
    base.setdefault("type", "personal")
    base.setdefault("pluginEnabled", True)
    base["areaInfoComplete"] = True
    base.setdefault("isCreator", False)
    base.setdefault("isAdmin", False)
    base.setdefault("isFirstLogin", False)
    base.setdefault("logOutEnable", False)
    base.setdefault("isCurrentOneIdPersonal", False)
    # 国内版旧客户端会把手机号一起加密；/v2/accounts 不返回它，别留旧号的。
    base.pop("phoneNumber", None)
    return base


def build_session(account, template, key, profiles=None):
    """构造目标账号的整份 session JSON（不落盘）。"""
    if account is None:
        raise ClientSwitchError("账号不存在")
    if getattr(account, "is_api_key", False):
        raise ClientSwitchError("静态 API Key 账号没有桌面客户端的登录身份，不能切")
    if not account.access_token or not account.refresh_token:
        raise ClientSwitchError("账号缺少 accessToken / refreshToken，无法构造客户端登录态")
    token_uid = wb_accounts.jwt_uid(account.access_token)
    if token_uid and account.uid and token_uid != account.uid:
        raise ClientSwitchError("accessToken 的 sub 与账号 uid 不一致，拒绝写入")
    profiles = profiles if profiles is not None else fetch_profiles(account)
    target = None
    for row in profiles:
        if str(row.get("uid")) == account.uid:
            target = row
            break
    if target is None:
        raise ClientSwitchError("上游档案里没有目标账号")

    cfg = wb_accounts.get_realm_config(account.realm)
    nickname = str(target.get("nickname") or account.nickname or account.uid[:8])
    account_doc = _merge_profile(template.get("account") or {}, target, account.uid)
    account_doc["nickname"] = wb_atrest.seal(key, nickname, "field")

    now_s = int(time.time())
    exp_s = int(account.expires_at or _jwt_exp(account.access_token) or 0)
    if exp_s > 10 ** 12:
        exp_s //= 1000
    refresh_exp_s = int(_jwt_exp(account.refresh_token) or exp_s)
    if refresh_exp_s > 10 ** 12:
        refresh_exp_s //= 1000
    claims = _jwt_claims(account.access_token)
    auth = dict(template.get("auth") or {})
    auth.update({
        "accessToken": wb_atrest.seal(key, account.access_token, "field"),
        "refreshToken": wb_atrest.seal(key, account.refresh_token, "field"),
        "expiresIn": max(0, exp_s - now_s),
        "refreshExpiresIn": max(0, refresh_exp_s - now_s),
        "tokenType": "Bearer",
        "sessionState": str(uuid.uuid4()),
        "scope": str(claims.get("scope") or auth.get("scope") or "openid profile offline_access email"),
        "domain": wb_accounts.domain_for_realm(account.realm, account.domain or cfg["domain"]),
        "lastRefreshTime": _now_ms(),
        "expiresAt": exp_s * 1000,
        "refreshExpiresAt": refresh_exp_s * 1000,
    })

    accounts = []
    for row in profiles:
        merged = _merge_profile(template.get("account") or {}, row, account.uid)
        merged["nickname"] = wb_atrest.seal(
            key, str(row.get("nickname") or merged.get("uid") or ""), "field")
        accounts.append(merged)
    if not any(str(row.get("uid")) == account.uid for row in accounts):
        accounts.insert(0, account_doc)

    return {
        "account": account_doc,
        "auth": auth,
        "accounts": accounts,
        "allAccounts": [dict(row) for row in accounts],
    }


def session_summary(doc, key):
    """回读校验：uid/nickname/token 都能用同一把 key 解出来。"""
    account = doc.get("account") or {}
    auth = doc.get("auth") or {}
    access = wb_atrest.decrypt_field(key, auth.get("accessToken"))
    refresh = wb_atrest.decrypt_field(key, auth.get("refreshToken"))
    nickname = wb_atrest.decrypt_field(key, account.get("nickname"))
    uid = str(account.get("uid") or "")
    if not uid or not access or not refresh:
        raise ClientSwitchError("回读校验失败：uid / token 解不出来")
    if wb_accounts.jwt_uid(access) != uid:
        raise ClientSwitchError("回读校验失败：token sub 与 uid 不一致")
    return {
        "uid": uid,
        "nickname": nickname or "",
        "uin": str(account.get("uin") or ""),
        "domain": str(auth.get("domain") or ""),
        "expiresAt": int(auth.get("expiresAt") or 0),
        "refreshExpiresAt": int(auth.get("refreshExpiresAt") or 0),
        "accessTokenLength": len(access),
    }


def wait_for_uid(path, uid, timeout=START_VERIFY_TIMEOUT):
    """客户端启动后会回写 auth 文件；等到 uid 变成目标值即视为生效。"""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            doc = read_session(path)
            last = str((doc.get("account") or {}).get("uid") or "")
            if last == uid:
                return True
        except Exception:
            pass
        if not client_pids():
            return False
        time.sleep(0.5)
    return last == uid


# ------------------------------------------------------------------ 对外入口
def status(accounts_dir=None):
    """给面板/CLI 的只读状态；任何异常都转成 error 字段，不抛。"""
    out = {"ok": True, "running": bool(client_pids()), "exe": client_exe()}
    try:
        path, realm = desktop_auth()
        out.update({"authPath": path, "realm": realm})
        key = None
        try:
            key = wb_accounts.desktop_atrest_key()
        except Exception as exc:
            out["keyError"] = str(exc)
        doc = read_session(path)
        account = doc.get("account") or {}
        auth = doc.get("auth") or {}
        out["uid"] = str(account.get("uid") or "")
        out["domain"] = str(auth.get("domain") or "")
        if key:
            try:
                out["nickname"] = wb_atrest.decrypt_field(key, account.get("nickname")) or ""
            except Exception:
                out["nickname"] = ""
        out["expiresAt"] = int(auth.get("expiresAt") or 0)
    except Exception as exc:
        out["ok"] = False
        out["error"] = str(exc)
    return out


def switch_account(account, accounts_dir=None, log=None, dry_run=False, sync_sessions=False, backup=True):
    """把 account 切换成桌面客户端当前登录账号。

    返回 dict（面板直接 JSON 化）。失败抛 ClientSwitchError；如果已经停过
    客户端、写过文件，会先回滚备份再重新拉起客户端，然后才抛错。
    面板默认 sync_sessions=False（会话合并由「同步会话」按钮单独触发）；
    独立切号脚本可以传 True，在同一个停/启周期里顺手合并本地会话。
    """
    accounts_dir = accounts_dir or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "accounts")
    if not _SWITCH_LOCK.acquire(False):
        raise ClientSwitchError("已有一个切号或同步操作在进行，请稍后再试")
    try:
        path, realm = desktop_auth()
        if account.realm and account.realm != realm:
            raise ClientSwitchError(
                "目标账号是%s，但本机客户端当前是%s；跨区不能靠换登录态文件切换"
                % (("国内版" if account.realm == "cn" else "国际版"),
                   ("国内版" if realm == "cn" else "国际版")))
        key = wb_accounts.desktop_atrest_key(log=log)
        template = read_session(path)
        profiles = fetch_profiles(account, log=log)
        doc = build_session(account, template, key, profiles)
        target = session_summary(doc, key)
        current = str((template.get("account") or {}).get("uid") or "")
        if current == account.uid and client_pids():
            return {"ok": True, "noop": True, "reason": "客户端已经是这个账号",
                    "target": target, "authPath": path, "realm": realm}

        if dry_run:
            return {"ok": True, "dryRun": True, "target": target, "currentUid": current,
                    "authPath": path, "realm": realm, "running": bool(client_pids()),
                    "backupRoot": os.path.join(accounts_dir, "agent-backups", "client-auth")}

        backup_dir = None
        backup_sha = ""
        stopped = []
        client_was_running = bool(client_pids())
        try:
            stopped = stop_client(log=log) if client_was_running else []
            template = read_session(path)
            backup_dir, backup_sha = ("", "")
            if backup:
                backup_dir, backup_sha = backup_auth(
                    path, accounts_dir, note="before switching to %s" % account.uid)
            retired_marker = _retire_logout_marker(path)
            doc = build_session(account, template, key, profiles)
            target = session_summary(doc, key)
            write_session(path, doc)
            verified_doc = read_session(path)
            readback = session_summary(verified_doc, key)
            if readback["uid"] != account.uid:
                raise ClientSwitchError("写入后回读 uid 不一致")
            session_sync = {}
            if sync_sessions:
                try:
                    session_sync = sync_local_sessions(
                        account.uid, accounts_dir, log=log, backup=backup)
                except Exception as exc:
                    session_sync = {"ok": False, "error": str(exc)}
                    _log(log, "local session sync failed: %s" % exc)
            started = start_client(log=log)
            applied = wait_for_uid(path, account.uid) if started else False
            result = {
                "ok": True,
                "target": readback,
                "authPath": path,
                "realm": realm,
                "backup": backup_dir,
                "backupSha256": backup_sha,
                "stopped": stopped,
                "started": started,
                "applied": applied,
                "retiredLogoutMarker": retired_marker,
                "sessions": session_sync,
            }
            if not applied:
                _log(log, "client switch written but uid not observed within %.0fs" % START_VERIFY_TIMEOUT)
            else:
                _log(log, "desktop client switched to %s (%s)" % (account.uid[:8], readback["nickname"]))
            return result
        except Exception as exc:
            _log(log, "client switch failed: %s" % exc)
            if backup_dir:
                try:
                    restored = 0
                    for name in os.listdir(backup_dir):
                        if name == "manifest.json":
                            continue
                        src = os.path.join(backup_dir, name)
                        if os.path.isfile(src):
                            shutil.copy2(src, os.path.join(os.path.dirname(path), name))
                            restored += 1
                    _log(log, "restored %d auth file(s) from %s" % (restored, backup_dir))
                except Exception as restore_exc:
                    _log(log, "restore backup failed: %s" % restore_exc)
            if client_was_running and not client_pids():
                try:
                    start_client(log=log)
                except Exception:
                    pass
            if isinstance(exc, ClientSwitchError):
                raise
            raise ClientSwitchError("切换失败：%s" % exc)
    finally:
        _SWITCH_LOCK.release()


# --------------------------------------------------------------------- CLI
def _cli(argv):
    pool = wb_accounts.AccountPool(
        os.environ.get("ACCOUNTS_DIR") or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "accounts"))
    pool.load()
    if not argv or argv[0] in ("status", "list"):
        print(json.dumps(status(accounts_dir=pool.dir), ensure_ascii=False, indent=2))
        return 0
    if argv[0] == "sessions-count" and len(argv) > 1:
        print(json.dumps(sync_local_sessions(argv[1], pool.dir, dry_run=True),
                         ensure_ascii=False, indent=2))
        return 0
    if argv[0] == "sessions-sync" and len(argv) > 1:
        print(json.dumps(sync_local_sessions(argv[1], pool.dir,
                                             log=lambda m: print(m, file=sys.stderr)),
                         ensure_ascii=False, indent=2))
        return 0
    if argv[0] == "prune-backups":
        print(json.dumps(prune_backups(pool.dir, log=lambda m: print(m, file=sys.stderr)),
                         ensure_ascii=False, indent=2))
        return 0
    if argv[0] == "sessions-restore":
        print(json.dumps(restore_session_owners(pool.dir,
                                                log=lambda m: print(m, file=sys.stderr)),
                         ensure_ascii=False, indent=2))
        return 0
    if argv[0] == "dry-run" and len(argv) > 1:
        account = pool.get(argv[1])
        if account is None:
            print("account not found", file=sys.stderr)
            return 2
        path, realm = desktop_auth()
        key = wb_accounts.desktop_atrest_key()
        template = read_session(path)
        profiles = fetch_profiles(account)
        doc = build_session(account, template, key, profiles)
        print(json.dumps({"ok": True, "authPath": path, "realm": realm,
                          "target": session_summary(doc, key)}, ensure_ascii=False, indent=2))
        return 0
    if argv[0] == "switch" and len(argv) > 1:
        account = pool.get(argv[1])
        if account is None:
            print("account not found", file=sys.stderr)
            return 2
        result = switch_account(account, accounts_dir=pool.dir, log=lambda m: print(m, file=sys.stderr))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    print("usage: python wb_client_switch.py [status|dry-run <uid>|switch <uid>|sessions-count <uid>|sessions-sync <uid>|sessions-restore]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
