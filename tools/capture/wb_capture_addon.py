# -*- coding: utf-8 -*-
"""wb_capture_addon.py —— mitmproxy 抓包插件：官方客户端流量 → 脱敏 JSONL

    mitmdump -p 8899 --mode local:WorkBuddyAI -s tools/capture/wb_capture_addon.py \
        --set wb_out=capture/lifecycle.jsonl --set wb_bodies=true

选项：wb_out / wb_hosts / wb_bodies / wb_body_limit / wb_include_assets

口径：只记「请求形状」（方法、路径模板、头名与顺序、body 字段集、gzip/SSE 标记），
凭据与个人标识在落盘前替换成 `<redacted:len>`。脱敏与形状提取是纯标准库，
不装 mitmproxy 也能被测试直接导入。
"""

import gzip
import json
import os
import re
import time

try:
    from mitmproxy import http  # noqa: F401
except Exception:  # pragma: no cover
    http = None

SCHEMA_VERSION = 1
DEFAULT_HOSTS = "workbuddy.ai,workbuddy.cn,tencent.com,codebuddy.cn,codebuddy.ai"
ASSET_SUFFIXES = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                  ".ico", ".woff", ".woff2", ".map", ".webp", ".mp4")

SECRET_HEADERS = {
    "authorization", "proxy-authorization", "x-api-key", "api-key",
    "cookie", "set-cookie", "x-user-id", "x-uid", "x-userid",
    "x-machine-id", "x-device-id", "x-session-id", "x-client-id",
    "sec-websocket-key",
}
# 2026-10-24 实测抓包复盘：X-Refresh-Token 是活凭证（可用它轮换 access
# token）、X-Device-Token 是本机 TuringShield 设备凭证，两者当时都不在
# SECRET_HEADERS 里、原样落了盘。头名脱敏不能只靠精确名单：凡是归一化后
# 的头名带 token/secret/password/cookie/apikey 等字样的一律掩码，形状
# （长度）保留。
SECRET_KEY_HINTS = (
    "token", "secret", "password", "passwd", "cookie", "apikey",
    "uid", "userid", "machineid", "sessionid", "deviceid",
    "email", "phone", "mobile", "authorization",
)

MASKED_MARK = "<redacted:"


def _norm_key(name):
    return re.sub(r"[-_]", "", str(name or "").lower())


def is_secret_header(name):
    key = str(name or "").lower()
    if key in SECRET_HEADERS:
        return True
    norm = _norm_key(name)
    return any(hint in norm for hint in SECRET_KEY_HINTS)

_HEX32 = re.compile(r"[0-9a-fA-F]{32}")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_LONG_NUM = re.compile(r"\b\d{5,}\b")


# ------------------------------------------------------------------ 脱敏

def mask_value(value):
    text = "" if value is None else str(value)
    prefix = ""
    head = text.split(" ", 1)
    if len(head) == 2 and head[0].isalpha() and len(head[0]) <= 12:
        prefix = head[0] + " "
    return "%s<redacted:%d>" % (prefix, len(text))


def redact_headers(pairs):
    out = []
    for name, value in pairs:
        if is_secret_header(name):
            out.append([name, mask_value(value)])
        else:
            out.append([name, value])
    return out


def redact_body(obj, depth=0):
    if depth > 12:
        return obj
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if any(hint in _norm_key(key) for hint in SECRET_KEY_HINTS):
                out[key] = mask_value(value if not isinstance(value, (dict, list))
                                      else json.dumps(value, ensure_ascii=False))
            else:
                out[key] = redact_body(value, depth + 1)
        return out
    if isinstance(obj, list):
        return [redact_body(item, depth + 1) for item in obj]
    return obj


# -------------------------------------------------------------- 形状提取

def path_template(path):
    tpl = _UUID.sub("{uuid}", str(path or "/"))
    tpl = _HEX32.sub("{hex32}", tpl)
    tpl = _LONG_NUM.sub("{n}", tpl)
    return tpl


def _decode(raw):
    if not raw:
        return b"", False
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw), True
        except (OSError, EOFError):
            return b"", True
    return raw, False


def summarize_body(raw, content_type="", limit=4096, want_text=False):
    info = {"len": len(raw or b"")}
    body, was_gzip = _decode(raw)
    if was_gzip:
        info["gzip"] = True
        info["decoded_len"] = len(body)
    if not body:
        return info, None

    ctype = str(content_type or "").lower()
    text = body[:limit]
    if "event-stream" in ctype or text[:6] == b"data: ":
        info["sse"] = True
        lines = body.split(b"\n")
        events = []
        for line in lines:
            if line.startswith(b"event:"):
                name = line[6:].strip().decode("utf-8", "replace")
                if name and (not events or events[-1] != name):
                    events.append(name)
            if len(events) >= 20:
                break
        info["sse_events"] = events
        info["sse_data_lines"] = sum(1 for line in lines if line.startswith(b"data:"))
    elif "json" in ctype or text[:1] in (b"{", b"["):
        try:
            payload = json.loads(body.decode("utf-8"))
            info["json"] = True
            if isinstance(payload, dict):
                info["keys"] = sorted(str(k) for k in payload.keys())[:60]
            elif isinstance(payload, list):
                info["list_len"] = len(payload)
            if want_text:
                text = json.dumps(redact_body(payload), ensure_ascii=False,
                                  indent=2).encode("utf-8")[:limit]
        except (ValueError, UnicodeDecodeError):
            info["json"] = False
    if want_text:
        return info, text.decode("utf-8", "replace")
    return info, None


def build_record(host, method, path, status, req_headers, req_body,
                 resp_headers=None, resp_body=None, resp_type="",
                 resp_len=None, body_limit=4096, want_text=False, ts=None):
    body_info, body_text = summarize_body(req_body, _header(req_headers,
                                                            "content-type"),
                                          body_limit, want_text)
    rec = {
        "kind": "flow",
        "ts": round(ts if ts is not None else time.time(), 3),
        "host": str(host or "").lower(),
        "method": str(method or "").upper(),
        "path": str(path or "/"),
        "path_tpl": path_template(path),
        "status": int(status or 0),
        "req_headers": redact_headers(list(req_headers or [])),
        "req_body": body_info,
    }
    if resp_headers is not None:
        length = resp_len if resp_len is not None else len(resp_body or b"")
        ctype = str(resp_type or _header(resp_headers, "content-type") or "")
        rec["resp"] = {"status": int(status or 0), "content_type": ctype,
                       "len": int(length or 0)}
        # SSE 不读 body：读了会把整段流缓冲下来，客户端首字延迟直接崩。
        if "event-stream" in ctype.lower():
            rec["resp"]["stream"] = True
    if body_text is not None:
        rec["req_body_text"] = body_text
    return rec


def _header(pairs, name):
    for key, value in pairs or []:
        if str(key or "").lower() == name:
            return value
    return ""


# ------------------------------------------------------------ mitmproxy 壳

def _option(name, default):
    try:
        from mitmproxy import ctx
        return getattr(ctx.options, name, default)
    except Exception:
        return default


class WBCapture(object):
    def __init__(self):
        self._fh = None
        self._path = None

    def load(self, loader):
        loader.add_option("wb_out", str, "capture/flows.jsonl", "抓包 JSONL 落盘路径")
        loader.add_option("wb_hosts", str, DEFAULT_HOSTS, "只记这些后缀的 host")
        loader.add_option("wb_bodies", bool, False, "是否落盘脱敏后的请求 body")
        loader.add_option("wb_body_limit", int, 4096, "单条 body 截断字节数")
        loader.add_option("wb_include_assets", bool, False, "是否记录静态资源")

    def _wanted(self, flow):
        host = (flow.request.pretty_host or "").lower()
        suffixes = [s.strip().lower() for s in
                    str(_option("wb_hosts", DEFAULT_HOSTS)).split(",") if s.strip()]
        if not any(host == s or host.endswith("." + s) for s in suffixes):
            return False
        path = (flow.request.path or "").lower().split("?", 1)[0]
        if not _option("wb_include_assets", False) and path.endswith(ASSET_SUFFIXES):
            return False
        return True

    def _open(self):
        if self._fh is not None:
            return self._fh
        path = str(_option("wb_out", "capture/flows.jsonl"))
        if path != self._path:
            self.close()
            directory = os.path.dirname(os.path.abspath(path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            self._fh = open(path, "a", encoding="utf-8")
            self._path = path
            self._write({"kind": "meta", "schema": SCHEMA_VERSION,
                         "tool": "wb_capture_addon", "at": time.time()})
        return self._fh

    def _write(self, rec):
        fh = self._fh
        if fh is None:
            return
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fh.flush()

    def response(self, flow):
        try:
            if not self._wanted(flow):
                return
            self._open()
            req, resp = flow.request, flow.response
            resp_pairs = list(resp.headers.items(multi=True)) if resp else None
            if resp is not None and "event-stream" in (
                    resp.headers.get("content-type", "") or "").lower():
                resp.stream = True  # 直通，别缓冲
            try:
                resp_len = int(resp.headers.get("content-length", "") or 0) if resp else 0
            except ValueError:
                resp_len = 0
            self._write(build_record(
                req.pretty_host, req.method, req.path,
                resp.status_code if resp is not None else 0,
                [[k, v] for k, v in req.headers.items(multi=True)],
                req.raw_content or b"",
                resp_headers=resp_pairs, resp_body=None,
                resp_type=(resp.headers.get("content-type", "") if resp else ""),
                resp_len=resp_len,
                body_limit=int(_option("wb_body_limit", 4096)),
                want_text=bool(_option("wb_bodies", False)),
            ))
        except Exception as exc:  # 抓包插件不能把 mitmdump 带崩
            try:
                from mitmproxy import ctx
                ctx.log.warn("wb_capture: %s" % exc)
            except Exception:
                pass

    def websocket_start(self, flow):
        """对话可能走 WS，握手头才是要对比的东西。"""
        try:
            if not self._wanted(flow):
                return
            self._open()
            rec = build_record(
                flow.request.pretty_host, flow.request.method, flow.request.path,
                101, [[k, v] for k, v in flow.request.headers.items(multi=True)],
                flow.request.raw_content or b"", resp_headers=None)
            rec["resp"] = {"status": 101, "content_type": "websocket",
                           "len": 0, "stream": True}
            self._write(rec)
        except Exception:
            pass

    def tls_failed_client(self, data):
        """客户端不认 CA 时留证据，否则只会看到「一条都没有」。"""
        try:
            conn = getattr(data, "conn", None)
            self._open()
            self._write({"kind": "tls_fail", "ts": time.time(),
                         "host": str(getattr(conn, "sni", "") or ""),
                         "hint": "客户端不认 mitmproxy CA；重启客户端让它读到新 bundle"})
        except Exception:
            pass

    def done(self):
        self.close()

    def close(self):
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None


addons = [WBCapture()]
