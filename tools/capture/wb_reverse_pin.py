# -*- coding: utf-8 -*-
"""wb_reverse_pin.py —— hosts 反向代理模式：把上游钉到真实 IP，并把 Host 拉回域名

为什么需要：hosts 把 `www.workbuddy.ai` 指到 127.0.0.1 后，mitmproxy 反向模式再按
域名解析上游会解析回自己（`server connect www.workbuddy.ai:443 (127.0.0.1:443)`）。
`dns_use_hosts_file` 只对 regular/wireguard 生效，对 reverse 无效，所以只能绕开解析：
外部先解析好真实 IP，这里在 `server_connect` 换地址，再用 `requestheaders` 把
Host / authority 拉回域名（否则请求行变成 `https://<ip>/...`，上游按 Host 路由直接 404）。

    mitmdump --mode reverse:https://www.workbuddy.ai@443 \
             -s wb_capture_addon.py -s wb_reverse_pin.py \
             --set wb_pin_ip=43.160.158.125 --set wb_pin_sni=www.workbuddy.ai

不设 `wb_pin_ip` 时完全不动。
"""

try:
    from mitmproxy import ctx
except Exception:  # pragma: no cover
    ctx = None


class ReversePin(object):
    def load(self, loader):
        loader.add_option("wb_pin_ip", str, "", "reverse 模式上游真实 IP（留空不干预）")
        loader.add_option("wb_pin_sni", str, "", "上游 TLS SNI / 主机名")

    def _opts(self):
        ip = str(getattr(ctx.options, "wb_pin_ip", "") or "").strip()
        host = str(getattr(ctx.options, "wb_pin_sni", "") or "").strip()
        return ip, host

    def requestheaders(self, flow):
        ip, host = self._opts()
        if not ip or not host:
            return
        flow.request.headers["Host"] = host
        if flow.request.host != host:
            flow.request.host = host

    def server_connect(self, data):
        ip, host = self._opts()
        if not ip:
            return
        data.server.address = (ip, 443)
        if host:
            data.server.sni = host


addons = [ReversePin()]
