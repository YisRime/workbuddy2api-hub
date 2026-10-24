"""响应解压层（DecodingResponse）与出站 Accept-Encoding 声明。"""
import gzip
import io
import os
import sys
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wb_accounts


class FakeRaw(object):
    def __init__(self, body, headers=None, length=0):
        self._io = io.BytesIO(body)
        self.headers = headers if headers is not None else {}
        self.length = length
        self.status = 200

    def read(self, size=-1):
        return self._io.read(size)

    def read1(self, size=-1):
        return self._io.read(size if (size is None or size > 0) else -1)

    def readline(self, size=-1):
        return self._io.readline(size)

    def close(self):
        self._io.close()


PLAIN = b'data: {"choices": []}\n\ndata: [DONE]\n\n'


def gz(data):
    return gzip.compress(data)


def raw_deflate(data):
    co = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return co.compress(data) + co.flush()


class DecodingResponseTests(unittest.TestCase):
    def test_gzip_full_read_and_lines(self):
        wrapped = wb_accounts.DecodingResponse(
            FakeRaw(gz(PLAIN), {"Content-Encoding": "gzip"}))
        self.assertEqual(wrapped.read(), PLAIN)
        # 逐行 / read1 路径（SSE 用）
        wrapped2 = wb_accounts.DecodingResponse(
            FakeRaw(gz(PLAIN), {"Content-Encoding": "gzip"}))
        self.assertEqual(wrapped2.readline(), b'data: {"choices": []}\n')
        chunks = []
        while True:
            piece = wrapped2.read1(65536)
            if not piece:
                break
            chunks.append(piece)
        self.assertTrue(b"[DONE]" in b"".join(chunks))

    def test_deflate_raw_and_zlib_container(self):
        wrapped = wb_accounts.DecodingResponse(
            FakeRaw(raw_deflate(PLAIN), {"Content-Encoding": "deflate"}))
        self.assertEqual(wrapped.read(), PLAIN)
        # 有些服务器把 zlib 容器当 deflate 发：首个块报错时换容器重解。
        zwrapped = wb_accounts.DecodingResponse(
            FakeRaw(zlib.compress(PLAIN), {"Content-Encoding": "deflate"}))
        self.assertEqual(zwrapped.read(), PLAIN)

    def test_gzip_length_is_zero_passthrough_keeps_raw(self):
        gzip_resp = wb_accounts.DecodingResponse(
            FakeRaw(gz(PLAIN), {"Content-Encoding": "gzip"}, length=99))
        self.assertEqual(gzip_resp.length, 0)   # 压缩体不做 length 截断启发
        plain_resp = wb_accounts.DecodingResponse(
            FakeRaw(PLAIN, {}, length=42))
        self.assertEqual(plain_resp.length, 42)
        self.assertEqual(plain_resp.read1(), PLAIN)

    def test_unknown_encoding_passes_through(self):
        wrapped = wb_accounts.DecodingResponse(
            FakeRaw(PLAIN, {"Content-Encoding": "br"}))
        self.assertEqual(wrapped.read(), PLAIN)

    def test_attributes_delegate_to_raw(self):
        raw = FakeRaw(PLAIN)
        wrapped = wb_accounts.DecodingResponse(raw)
        self.assertEqual(wrapped.status, 200)
        wrapped.marker = "slot"          # 槽位绑定之类 setattr 仍可用
        self.assertEqual(wrapped.marker, "slot")

    def test_close_closes_both_layers(self):
        raw = FakeRaw(gz(PLAIN), {"Content-Encoding": "gzip"})
        wrapped = wb_accounts.DecodingResponse(raw)
        with wrapped as resp:
            self.assertIs(resp, wrapped)
        self.assertTrue(raw._io.closed)


class AcceptEncodingHeaderTests(unittest.TestCase):
    def _account(self, realm, product="workbuddy"):
        return wb_accounts.Account({
            "uid": "u-ae", "realm": realm,
            "domain": "www.workbuddy.ai" if realm == "intl" else "www.workbuddy.cn",
            "accessToken": "t", "product": product})

    def test_intl_chat_declares_gzip_deflate(self):
        for product in ("workbuddy", "cli", "vscode"):
            headers = self._account("intl", product).headers(purpose="chat")
            self.assertEqual(headers.get("Accept-Encoding"), "gzip, deflate",
                             product)

    def test_cn_chat_stays_undclared(self):
        headers = self._account("cn").headers(purpose="chat")
        self.assertNotIn("Accept-Encoding", headers)

    def test_refresh_billing_console_follow_realm(self):
        intl = self._account("intl")
        self.assertEqual(intl._refresh_headers().get("Accept-Encoding"),
                         "gzip, deflate")
        self.assertEqual(intl.headers(purpose="billing").get("Accept-Encoding"),
                         "gzip, deflate")
        self.assertEqual(intl._desktop_console_headers().get("Accept-Encoding"),
                         "gzip, deflate")
        cn = self._account("cn")
        self.assertNotIn("Accept-Encoding", cn._refresh_headers())
        self.assertNotIn("Accept-Encoding", cn.headers(purpose="billing"))
        self.assertNotIn("Accept-Encoding", cn._desktop_console_headers())


if __name__ == "__main__":
    unittest.main(verbosity=2)
