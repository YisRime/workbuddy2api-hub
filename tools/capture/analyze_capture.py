# -*- coding: utf-8 -*-
"""analyze_capture.py —— 读 wb_capture_addon 落盘的 JSONL，做摘要 / 对比 / 常量核对

    python tools/capture/analyze_capture.py capture/lifecycle.jsonl              # 摘要
    ... --headers        # 附请求头清单
    ... --timeline       # 按时间顺序看整条生命周期
    ... --coverage       # 客户端逻辑 vs 网关逻辑（接口覆盖）
    ... --identity       # 抓包 UA/版本 vs wb_identity 常量
    ... --surface        # 输出 markdown 接口面表格（贴进文档用）
    ... --diff baseline.jsonl   # 与上一次抓包对比

纯标准库。有差异时退出码 1。
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

VOLATILE_HEADERS = {
    "x-conversation-request-id", "x-request-id", "x-trace-id", "traceparent",
    "x-message-id", "x-root-request-id", "x-conversation-id", "date",
    "content-length", "x-amzn-trace-id", "x-client-trace-id",
    "sec-websocket-key", "x-b3-traceid", "x-b3-spanid", "b3",
}

#: 客户端代码里实测出现的接口（CLI dist / main server.js）。
CLIENT_PATHS = OrderedDict([
    ("/v2/auth/token/wxide", "临时码换 token（登录）"),
    ("/v2/accounts", "账号列表（CLI 路径）"),
    ("/v2/plugin/accounts", "账号列表（桌面端实测）"),
    ("/v2/auth/token/refresh", "刷新 token（CLI 路径）"),
    ("/v2/plugin/auth/token/refresh", "刷新 token（桌面端实测）"),
    ("/v3/config", "配置 / 模型目录"),
    ("/v2/chat/completions", "对话（API 路径，桌面端未使用）"),
    ("/v2/agentos/localagent/workspaces/websocket", "agent 通道（WebSocket）"),
    ("/console/as/conversations/", "会话列表"),
    ("/space/api/agent/v1/mcp", "agent MCP 通道"),
    ("/billing/meter/get-user-resource-summary", "配额"),
    ("/v2/spans", "OTel 链路上报"),
])

REPO_PATH_ATTRS = (
    ("wb_accounts", "PROFILE_PATH"),
    ("wb_accounts", "AUTH_STATE_PATH"),
    ("wb_accounts", "AUTH_TOKEN_PATH"),
    ("wb_accounts", "LOGIN_ACCOUNT_PATH"),
    ("wb_accounts", "REFRESH_PATH"),
    ("wb_accounts", "CHECKIN_PATH"),
    ("wb_accounts", "GET_RESOURCE_PATH"),
    ("wb_accounts", "RESOURCE_SUMMARY_PATH"),
    ("wb_accounts", "CHECKIN_STATUS_PATH"),
    ("wb_accounts", "ENTERPRISE_USAGE_PATH"),
    ("wb_proxy", "REMOTE_CONFIG_PATH"),
    ("wb_proxy", "CHAT_PATH"),
)


def load(path):
    flows, fails = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("kind") == "flow":
                flows.append(rec)
            elif rec.get("kind") == "tls_fail":
                fails.append(rec)
    return flows, fails


def bare(path):
    return str(path or "").split("?", 1)[0]


def group_key(rec):
    return (rec.get("host", ""), rec.get("method", ""),
            rec.get("path_tpl") or bare(rec.get("path")))


def group(records):
    out = OrderedDict()
    for rec in records:
        out.setdefault(group_key(rec), []).append(rec)
    return out


def header_names(records):
    names = OrderedDict()
    for rec in records:
        for name, _value in rec.get("req_headers") or []:
            key = str(name).lower()
            names[key] = names.get(key, 0) + 1
    return names


def header_value(records, name):
    seen = []
    for rec in records:
        for key, value in rec.get("req_headers") or []:
            if str(key).lower() == name and value not in seen:
                seen.append(value)
    return seen


def body_keys(records):
    keys = OrderedDict()
    for rec in records:
        for key in (rec.get("req_body") or {}).get("keys") or []:
            keys[key] = keys.get(key, 0) + 1
    return keys


# ------------------------------------------------------------------ 摘要

def print_summary(flows, fails, show_headers=False):
    if not flows:
        print("没有匹配的记录。检查 host 白名单，或客户端根本没走代理。")
        return
    groups = group(flows)
    print("%-26s %-6s %-46s %5s  %s" % ("host", "method", "path_tpl", "n", "status"))
    print("-" * 104)
    for (host, method, path), recs in groups.items():
        statuses = Counter(str(r.get("status")) for r in recs)
        status = ", ".join("%s×%d" % (c, n) for c, n in statuses.most_common(3))
        print("%-26s %-6s %-46s %5d  %s" % (host, method, path[:46], len(recs), status))
    print("\n共 %d 条 flow / %d 个接口" % (len(flows), len(groups)))
    if fails:
        by_host = Counter(f.get("host", "?") for f in fails)
        print("TLS 握手失败 %d 条：%s" % (len(fails),
              ", ".join("%s×%d" % (h, n) for h, n in by_host.most_common(5))))

    if show_headers:
        for (host, method, path), recs in groups.items():
            names = header_names(recs)
            print("\n[%s %s%s] 请求头 %d 个：" % (method, host, path, len(names)))
            for name, count in names.items():
                print("  %-32s %d/%d" % (name, count, len(recs)))


# ------------------------------------------------------------ markdown 接口面

def surface(flows, fails):
    """生成 markdown 表格：按 host 分组，列 接口 / 次数 / 状态。"""
    lines = []
    by_host = OrderedDict()
    for rec in flows:
        by_host.setdefault(rec.get("host", ""), []).append(rec)
    for host in sorted(by_host, key=lambda h: -len(by_host[h])):
        recs = by_host[host]
        groups = group(recs)
        lines.append("### %s（%d 条 / %d 个接口）\n" % (host, len(recs), len(groups)))
        lines.append("| 接口 | 次数 | 状态 |")
        lines.append("|---|---|---|")
        for (h, method, path), items in sorted(
                groups.items(), key=lambda kv: -len(kv[1])):
            statuses = Counter(str(r.get("status")) for r in items)
            status = ", ".join("%s×%d" % (c, n) for c, n in statuses.most_common(3))
            lines.append("| `%s %s` | %d | %s |" % (method, bare(path), len(items), status))
        lines.append("")
    if fails:
        lines.append("### TLS 握手失败（原生 SDK 证书固定）\n")
        by_host = Counter(f.get("host", "?") for f in fails)
        lines.append("| 域名 | 失败次数 |")
        lines.append("|---|---|")
        for host, count in by_host.most_common():
            lines.append("| `%s` | %d |" % (host, count))
        lines.append("")
    return lines


# ------------------------------------------------------------------ 生命周期

def print_timeline(flows, limit=0):
    if not flows:
        print("没有记录。")
        return
    ordered = sorted(flows, key=lambda r: float(r.get("ts") or 0))
    base = float(ordered[0].get("ts") or 0)
    for rec in (ordered[:limit] if limit else ordered):
        rel = float(rec.get("ts") or 0) - base
        flags = []
        if (rec.get("resp") or {}).get("stream"):
            flags.append("stream")
        if (rec.get("req_body") or {}).get("gzip"):
            flags.append("gzip")
        print("+%7.2fs  %-6s %-26s %-40s %s%s" % (
            rel, rec.get("method", ""), rec.get("host", ""),
            bare(rec.get("path"))[:40], rec.get("status", 0),
            ("  [" + ",".join(flags) + "]") if flags else ""))
    print("\n共 %d 条，跨度 %.1fs" % (
        len(ordered), float(ordered[-1].get("ts") or 0) - base))


# ------------------------------------------------------------ 逻辑覆盖

def repo_paths():
    import importlib
    import tempfile
    paths = OrderedDict()
    sandbox = tempfile.mkdtemp(prefix="wb-paths-")
    os.environ.setdefault("ACCOUNTS_DIR", sandbox)
    os.environ.setdefault("WB_PROXY_USAGE_DIR", sandbox)
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    for module_name, attr in REPO_PATH_ATTRS:
        value = ""
        try:
            module = importlib.import_module(module_name)
            value = str(getattr(module, attr, "") or "")
        except Exception:
            try:
                source = open(os.path.join(ROOT, module_name + ".py"),
                              encoding="utf-8").read()
                match = re.search(r'^%s\s*=\s*"([^"]+)"' % attr, source, re.M)
                value = match.group(1) if match else ""
            except Exception:
                value = ""
        if value.startswith("/"):
            paths[value] = "%s.%s" % (module_name, attr)
    return paths


def coverage(flows):
    seen = Counter(bare(r.get("path_tpl") or r.get("path")) for r in flows)
    repo = repo_paths()
    client_only = [p for p in CLIENT_PATHS if p not in repo]
    repo_only = [p for p in repo if p not in CLIENT_PATHS]
    lines = ["%-48s %-6s %-6s %s" % ("path", "客户端", "网关", "本次抓到"),
             "-" * 80]
    for path in list(CLIENT_PATHS) + [p for p in repo if p not in CLIENT_PATHS]:
        lines.append("%-48s %-6s %-6s %s" % (
            path[:48],
            "有" if path in CLIENT_PATHS else "-",
            "有" if path in repo else "-",
            ("%d 次" % seen[path]) if seen.get(path) else "-"))
    return lines, client_only, repo_only


def print_coverage(flows):
    lines, client_only, repo_only = coverage(flows)
    print("\n=== 客户端逻辑 vs 网关逻辑 ===")
    print("\n".join(lines))
    if client_only:
        print("\n客户端有、网关没有：")
        for path in client_only:
            print("  - %-46s %s" % (path, CLIENT_PATHS.get(path, "")))
    if repo_only:
        print("\n网关有、本次抓包未见：")
        repo = repo_paths()
        for path in repo_only:
            print("  - %-46s %s" % (path, repo.get(path, "")))
    print("\n注：客户端清单来自 CLI dist 与 main/server.js 静态提取；网关侧来自 *_PATH 常量。")


# ------------------------------------------------------------ 常量核对

def identity_drift(flows):
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    import wb_identity as ident
    lines, drift = [], False
    realms = [
        ("国际版桌面端", ("workbuddy.ai",), "DESKTOP_VERSION_INTL", "DESKTOP_UA_INTL"),
        ("国内版桌面端", ("workbuddy.cn", "copilot.tencent.com"),
         "DESKTOP_VERSION_CN", "DESKTOP_UA_CN"),
    ]
    for label, hosts, ver_name, ua_name in realms:
        subset = [r for r in flows
                  if any(h in r.get("host", "") for h in hosts)
                  and (header_value([r], "user-agent") or [""])[0]
                  .startswith(("WorkBuddy/", "workbuddy-ai/"))]
        if not subset:
            lines.append("· %s：本次抓包没有对应请求，跳过" % label)
            continue
        realm_drift = False
        expect_ver = getattr(ident, ver_name, "")
        expect_ua = getattr(ident, ua_name, "")
        for observed in [v for v in header_value(subset, "x-ide-version") if v]:
            if observed != expect_ver:
                realm_drift = True
                lines.append("! %s 版本漂移：抓包 %s ≠ %s=%s"
                             % (label, observed, ver_name, expect_ver))
        for ua in header_value(subset, "user-agent"):
            if ua != expect_ua:
                realm_drift = True
                lines.append("! %s UA 漂移：\n    抓包 %s\n    常量 %s（%s）"
                             % (label, ua, expect_ua, ua_name))
        if not realm_drift:
            lines.append("· %s：版本 %s / UA 与常量一致" % (label, expect_ver or "(无)"))
        drift = drift or realm_drift
    return lines, drift


# ------------------------------------------------------------------ diff

def diff(base_flows, new_flows):
    base, new = group(base_flows), group(new_flows)
    lines = []
    for host, method, path in [k for k in new if k not in base]:
        lines.append("  + 新接口  %s %s%s" % (method, host, path))
    for host, method, path in [k for k in base if k not in new]:
        lines.append("  - 消失    %s %s%s" % (method, host, path))
    for key in new:
        if key not in base:
            continue
        host, method, path = key
        old_names, new_names = header_names(base[key]), header_names(new[key])
        plus = [n for n in new_names if n not in old_names]
        minus = [n for n in old_names if n not in new_names]
        if plus or minus:
            lines.append("  %s %s%s 头族变化" % (method, host, path))
            lines += ["    + %s" % n for n in plus] + ["    - %s" % n for n in minus]
        old_keys, new_keys = body_keys(base[key]), body_keys(new[key])
        plus_keys = [k for k in new_keys if k not in old_keys]
        minus_keys = [k for k in old_keys if k not in new_keys]
        if plus_keys or minus_keys:
            lines.append("  %s %s%s 请求体字段变化" % (method, host, path))
            lines += ["    + %s" % n for n in plus_keys] + ["    - %s" % n for n in minus_keys]
        for name in ("user-agent", "x-ide-version", "x-ide-name", "x-ide-type", "x-product"):
            if name in VOLATILE_HEADERS:
                continue
            old_vals, new_vals = header_value(base[key], name), header_value(new[key], name)
            if old_vals != new_vals:
                lines.append("  %s %s%s %s" % (method, host, path, name))
                lines.append("    - %s" % " | ".join(old_vals))
                lines.append("    + %s" % " | ".join(new_vals))
    return lines


# ------------------------------------------------------------------ CLI

def main(argv=None):
    parser = argparse.ArgumentParser(description="分析 WorkBuddy 抓包 JSONL")
    parser.add_argument("capture")
    parser.add_argument("--headers", action="store_true")
    parser.add_argument("--timeline", action="store_true")
    parser.add_argument("--timeline-limit", type=int, default=80)
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--identity", action="store_true")
    parser.add_argument("--surface", action="store_true", help="输出 markdown 接口面")
    parser.add_argument("--diff", metavar="BASELINE")
    parser.add_argument("--host", help="只看包含该子串的 host")
    args = parser.parse_args(argv)

    flows, fails = load(args.capture)
    if args.host:
        flows = [r for r in flows if args.host in r.get("host", "")]
        fails = [f for f in fails if args.host in f.get("host", "")]

    if args.surface:
        print("\n".join(surface(flows, fails)))
        return 0

    print_summary(flows, fails, show_headers=args.headers)
    if args.timeline:
        print("\n=== 生命周期 ===")
        print_timeline(flows, args.timeline_limit)
    if args.coverage:
        print_coverage(flows)

    failed = False
    if args.diff:
        base_flows, _ = load(args.diff)
        lines = diff(base_flows, flows)
        print("\n=== 与基线对比 (%s) ===" % args.diff)
        print("\n".join(lines) if lines else "无差异。")
        failed = bool(lines)
    if args.identity:
        lines, drift = identity_drift(flows)
        print("\n=== 与 wb_identity.py 核对 ===")
        print("\n".join(lines))
        failed = failed or drift
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
