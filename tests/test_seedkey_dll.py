"""BAIC_B50_SeedKey.dll 与 Python baic-df-token 实现交叉校验（需先运行 tools/seedkey_dll/build.bat）。"""

import ctypes
import os
import struct
import unittest
from pathlib import Path

from doip_tester.uds.client_factory import (
    _aes128_cmac,
    _make_baic_v2_security_algo,
)

_ROOT = Path(__file__).resolve().parents[1]
_ARCH = "x64" if struct.calcsize("P") == 8 else "x86"
_DLL_PATH = _ROOT / "tools" / "seedkey_dll" / "build" / _ARCH / "BAIC_B50_SeedKey.dll"

_KEY_L1 = bytes.fromhex("F66EF1DE91B987096FEF02AFE2307FC6")
_KEY_L3 = bytes.fromhex("9848BFCD817E43449312039EA703DB79")

_U8P = ctypes.POINTER(ctypes.c_ubyte)
_U32P = ctypes.POINTER(ctypes.c_uint)


def _buf(data: bytes):
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


@unittest.skipUnless(os.name == "nt" and _DLL_PATH.is_file(), "seed-key DLL not built")
class TestSeedKeyDll(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dll = ctypes.CDLL(str(_DLL_PATH))
        dll.GenerateKeyEx.restype = ctypes.c_int
        dll.GenerateKeyEx.argtypes = [
            _U8P, ctypes.c_uint, ctypes.c_uint, ctypes.c_char_p, _U8P, ctypes.c_uint, _U32P,
        ]
        dll.GenerateKeyExOpt.restype = ctypes.c_int
        dll.GenerateKeyExOpt.argtypes = [
            _U8P, ctypes.c_uint, ctypes.c_uint, ctypes.c_char_p, ctypes.c_char_p,
            _U8P, ctypes.c_uint, _U32P,
        ]
        dll.B50_ComputeKeyWithDF.restype = ctypes.c_int
        dll.B50_ComputeKeyWithDF.argtypes = [
            _U8P, ctypes.c_uint, ctypes.c_uint, _U8P, _U8P, ctypes.c_uint, _U32P,
        ]
        dll.B50_AesCmac.restype = None
        dll.B50_AesCmac.argtypes = [_U8P, _U8P, ctypes.c_uint, _U8P]
        cls.dll = dll

    def _cmac(self, key: bytes, msg: bytes) -> bytes:
        out = (ctypes.c_ubyte * 16)()
        self.dll.B50_AesCmac(_buf(key), _buf(msg) if msg else None, len(msg), out)
        return bytes(out)

    def _key_with_df(self, seed: bytes, level: int, df: bytes):
        out = (ctypes.c_ubyte * 64)()
        n = ctypes.c_uint(0)
        rc = self.dll.B50_ComputeKeyWithDF(_buf(seed), len(seed), level, _buf(df), out, 64, ctypes.byref(n))
        return rc, bytes(out[: n.value])

    def _generate(self, seed: bytes, level: int, max_len: int = 64):
        out = (ctypes.c_ubyte * max(max_len, 1))()
        n = ctypes.c_uint(0)
        rc = self.dll.GenerateKeyEx(_buf(seed), len(seed), level, b"", out, max_len, ctypes.byref(n))
        return rc, bytes(out[: n.value])

    def test_cmac_rfc4493_vectors(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        msg = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        cases = {
            0: "bb1d6929e95937287fa37d129b756746",
            16: "070a16b46b4d4144f79bdd9dd04a287c",
            40: "dfa66747de9ae63030ca32611497c827",
            64: "51f0bebf7e3b9d92fc49741779363cfe",
        }
        for n, mac in cases.items():
            self.assertEqual(self._cmac(key, msg[:n]).hex(), mac, "len=%d" % n)

    def test_matches_python_baic_v2(self):
        seed = bytes.fromhex("1042d28073779e0ef597dd6bc3c3c109")
        df = bytes.fromhex("95149055d9bbfa4d6a068cbf306c93dc")
        algo = _make_baic_v2_security_algo(_KEY_L1, _KEY_L3, df_source=lambda n: df)
        for level, py_level in ((0x01, 0x01), (0x02, 0x01), (0x11, 0x11), (0x12, 0x11)):
            rc, key = self._key_with_df(seed, level, df)
            self.assertEqual(rc, 0)
            self.assertEqual(key, algo(seed, py_level), "level=0x%02X" % level)

    def test_generate_key_ex_random_df_verifies(self):
        seed = os.urandom(16)
        for level, master in ((0x01, _KEY_L1), (0x11, _KEY_L3)):
            rc, key = self._generate(seed, level)
            self.assertEqual(rc, 0)
            self.assertEqual(len(key), 32)
            df, token = key[:16], key[16:]
            self.assertEqual(token, _aes128_cmac(_aes128_cmac(master, df), seed))
        rc1, k1 = self._generate(seed, 0x01)
        rc2, k2 = self._generate(seed, 0x01)
        self.assertNotEqual(k1[:16], k2[:16])

    def test_generate_key_ex_opt(self):
        seed = os.urandom(16)
        out = (ctypes.c_ubyte * 32)()
        n = ctypes.c_uint(0)
        rc = self.dll.GenerateKeyExOpt(_buf(seed), 16, 0x11, b"", b"", out, 32, ctypes.byref(n))
        self.assertEqual(rc, 0)
        self.assertEqual(n.value, 32)
        key = bytes(out)
        self.assertEqual(key[16:], _aes128_cmac(_aes128_cmac(_KEY_L3, key[:16]), seed))

    def test_error_codes(self):
        seed = os.urandom(16)
        self.assertEqual(self._generate(seed, 0x03)[0], 2)
        self.assertEqual(self._generate(seed, 0x01, max_len=31)[0], 1)
        self.assertEqual(self._generate(seed[:4], 0x01)[0], 4)


if __name__ == "__main__":
    unittest.main()
