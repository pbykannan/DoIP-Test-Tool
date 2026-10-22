import tempfile
import unittest
import zipfile
from pathlib import Path

from doip_tester.config.models import RoutineStep
from doip_tester.flash.transfer import (
    TransferItem,
    _inject_signatures_for_rid_0202,
    _prepare_transfer_items_from_path,
    parse_signature_xml,
)
from doip_tester.uds.client_factory import (
    _make_baic_v2_security_algo,
    baic_v2_compute_token,
    baic_v2_derive_session_key,
)

# 《UDS安全访问认证方案 v2.0》附录 A 示例向量（Key/DF/SK/Seed/Token）
_REF_KEY = bytes.fromhex("01020304050607080102030405060708")
_REF_DF = bytes.fromhex("1F9D6DC2CCF3E59C160081E64E2D8899")
_REF_SK = bytes.fromhex("303567F173BC9C9EEA609791E4CB7E02")
_REF_SEED = bytes.fromhex("FAA79BC20CD6D2CEC54AFA2DBC9B51F6")
_REF_TOKEN = bytes.fromhex("497096BFFCFB7E62F538A83CBD5C40CB")

# 北汽 5-*.xml 签名清单模板（fileName 无扩展名，fileSIG 为 256 字节 = 512 hex）
def _make_signature_xml(root: Path, s19_name: str, zip_name: str) -> Path:
    sig_s19 = bytes(range(256))
    sig_zip = bytes(reversed(range(256)))
    xml = root / "5-CRC_TBX_V001.xml"
    xml.write_text(
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        "<FileListFactory>\n"
        "    <SIGVersion>1</SIGVersion>\n"
        "    <list>\n"
        "        <fileName>%s</fileName>\n"
        "        <fileSIG>%s</fileSIG>\n"
        "    </list>\n"
        "    <list>\n"
        "        <fileName>%s</fileName>\n"
        "        <fileSIG>%s</fileSIG>\n"
        "    </list>\n"
        "</FileListFactory>\n"
        % (s19_name, sig_s19.hex(), zip_name, sig_zip.hex()),
        encoding="utf-8",
    )
    return xml


class TestBaicV2SecurityAlgorithm(unittest.TestCase):
    def test_pdf_appendix_a_derive_session_key(self) -> None:
        sk = baic_v2_derive_session_key(_REF_KEY, _REF_DF)
        self.assertEqual(sk, _REF_SK)

    def test_pdf_appendix_a_compute_token(self) -> None:
        token = baic_v2_compute_token(_REF_SK, _REF_SEED)
        self.assertEqual(token, _REF_TOKEN)

    def test_algo_level1_returns_df_plus_token(self) -> None:
        algo = _make_baic_v2_security_algo(_REF_KEY, _REF_KEY, df_source=lambda n: _REF_DF)
        key = algo(_REF_SEED, 0x01)
        self.assertEqual(len(key), 32)
        self.assertEqual(key[:16], _REF_DF)
        self.assertEqual(key[16:], _REF_TOKEN)

    def test_algo_level3_uses_boot_key(self) -> None:
        boot_key = bytes.fromhex("9848BFCD817E43449312039EA703DB79")
        algo = _make_baic_v2_security_algo(_REF_KEY, boot_key, df_source=lambda n: _REF_DF)
        sk_boot = baic_v2_derive_session_key(boot_key, _REF_DF)
        token_boot = baic_v2_compute_token(sk_boot, _REF_SEED)
        key = algo(_REF_SEED, 0x11)
        self.assertEqual(key[:16], _REF_DF)
        self.assertEqual(key[16:], token_boot)

    def test_algo_rejects_wrong_seed_length(self) -> None:
        algo = _make_baic_v2_security_algo(_REF_KEY, _REF_KEY, df_source=lambda n: _REF_DF)
        with self.assertRaises(ValueError):
            algo(b"\x00" * 4, 0x01)


class TestS19ZipPairing(unittest.TestCase):
    def test_directory_s19_zip_pair(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s19 = root / "TBOX_APP_20260810.s19"
            zf = root / "TBOX_APP_20260810.zip"
            s19.write_bytes(b"\x11" * 256)
            zf.write_bytes(b"\x22" * 1024)
            _make_signature_xml(root, "TBOX_APP_20260810", "TBOX_APP_20260810")
            items, sig = _prepare_transfer_items_from_path(root, lambda _m: None)
            self.assertIsNone(sig)
            self.assertEqual(len(items), 2)
            self.assertEqual(items[0].name, s19.name)
            self.assertEqual(items[1].name, zf.name)
            self.assertEqual(items[0].size, 256)
            self.assertEqual(items[1].size, 1024)
            self.assertIsNotNone(items[0].signature)
            self.assertIsNotNone(items[1].signature)

    def test_select_single_s19_matches_sibling_zip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s19 = root / "flash.s19"
            zf = root / "flash.zip"
            s19.write_bytes(b"\x01" * 8)
            zf.write_bytes(b"\x02" * 8)
            _make_signature_xml(root, "flash", "flash")
            items, _sig = _prepare_transfer_items_from_path(s19, lambda _m: None)
            self.assertEqual(len(items), 2)
            self.assertEqual(items[0].name, "flash.s19")
            self.assertEqual(items[1].name, "flash.zip")

    def test_select_single_zip_matches_sibling_s19(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s19 = root / "flash.s19"
            zf = root / "flash.zip"
            s19.write_bytes(b"\x01" * 8)
            zf.write_bytes(b"\x02" * 8)
            _make_signature_xml(root, "flash", "flash")
            items, _sig = _prepare_transfer_items_from_path(zf, lambda _m: None)
            self.assertEqual(items[0].name, "flash.s19")
            self.assertEqual(items[1].name, "flash.zip")

    def test_missing_zip_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            s19 = Path(td) / "only.s19"
            s19.write_bytes(b"\x00")
            with self.assertRaises(ValueError):
                _prepare_transfer_items_from_path(s19, lambda _m: None)

    def test_missing_signature_xml_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "1-a.s19").write_bytes(b"\x01" * 8)
            (root / "2-b.zip").write_bytes(b"\x02" * 8)
            with self.assertRaises(FileNotFoundError):
                _prepare_transfer_items_from_path(root, lambda _m: None)

    def test_missing_one_file_signature_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s19 = root / "1-a.s19"
            zf = root / "2-b.zip"
            s19.write_bytes(b"\x01" * 8)
            zf.write_bytes(b"\x02" * 8)
            _make_signature_xml(root, "1-a", "2-b")
            # 改名使 zip 与清单名不匹配
            zf.rename(root / "2-c.zip")
            with self.assertRaises(ValueError):
                _prepare_transfer_items_from_path(root, lambda _m: None)

    def test_directory_with_both_cbf_and_s19_zip_prefers_s19_zip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.cbf").write_bytes(b"\x01" * 4)
            (root / "a.rsa").write_text(", ".join("0x%02X" % i for i in range(384)), encoding="ascii")
            (root / "b.s19").write_bytes(b"\x02" * 8)
            (root / "b.zip").write_bytes(b"\x03" * 8)
            _make_signature_xml(root, "b", "b")
            items, sig = _prepare_transfer_items_from_path(root, lambda _m: None)
            self.assertIsNone(sig)
            self.assertEqual([i.name for i in items], ["b.s19", "b.zip"])

    def test_directory_attaches_signatures_from_5_xml(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s19 = root / "1-TBX_E00156231_V001.s19"
            zf = root / "2-TBXE0015623112.18.02A01N80.zip"
            s19.write_bytes(b"\x11" * 256)
            zf.write_bytes(b"\x22" * 1024)
            _make_signature_xml(root, "1-TBX_E00156231_V001", "2-TBXE0015623112")
            items, sig = _prepare_transfer_items_from_path(root, lambda _m: None)
            self.assertIsNone(sig)
            self.assertEqual(len(items), 2)
            # zip stem 带版本后缀，匹配以清单 fileName 为前缀
            self.assertEqual(items[0].signature, bytes(range(256)))
            self.assertEqual(items[1].signature, bytes(reversed(range(256))))
            self.assertEqual(len(items[0].signature), 256)
            self.assertEqual(len(items[1].signature), 256)

    def test_select_single_xml_matches_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s19 = root / "1-flash.s19"
            zf = root / "2-flash.zip"
            s19.write_bytes(b"\x01" * 8)
            zf.write_bytes(b"\x02" * 8)
            xml = _make_signature_xml(root, "1-flash", "2-flash")
            items, _sig = _prepare_transfer_items_from_path(xml, lambda _m: None)
            self.assertEqual(len(items), 2)
            self.assertEqual(items[0].signature, bytes(range(256)))
            self.assertEqual(items[1].signature, bytes(reversed(range(256))))



class TestS19TarB40L(unittest.TestCase):
    """B40L：S19+TAR；同目录有 zip 时仍优先 zip（不破坏 n80ks）。"""

    def test_directory_s19_tar_pair(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s19 = root / "1-TBX_PART_V001.s19"
            tar = root / "2-TBXPART26.09.17.00A01B40L.tar"
            s19.write_bytes(b"\x11" * 64)
            tar.write_bytes(b"\x22" * 128)
            _make_signature_xml(root, "1-TBX_PART_V001", "2-TBXPART26.09.17.00A01B40L")
            items, sig = _prepare_transfer_items_from_path(root, lambda _m: None)
            self.assertIsNone(sig)
            self.assertEqual([i.name for i in items], [s19.name, tar.name])
            self.assertEqual(len(items[0].signature), 256)
            self.assertEqual(len(items[1].signature), 256)

    def test_zip_preferred_when_both_zip_and_tar(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s19 = root / "flash.s19"
            zf = root / "flash.zip"
            tar = root / "flash.tar"
            s19.write_bytes(b"\x01" * 8)
            zf.write_bytes(b"\x02" * 8)
            tar.write_bytes(b"\x03" * 8)
            _make_signature_xml(root, "flash", "flash")
            items, _ = _prepare_transfer_items_from_path(root, lambda _m: None)
            self.assertEqual(items[1].name, "flash.zip")

    def test_doip_package_with_tar(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = root / "DoIP-TBX26.09.17.00B40L.zip"
            xml = _make_signature_xml(
                root, "1-TBX_PART_V001", "2-TBXPART26.09.17.00A01B40L"
            )
            with zipfile.ZipFile(str(pkg), "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("1-TBX_PART_V001.s19", b"\x11" * 40)
                zf.writestr("2-TBXPART26.09.17.00A01B40L.tar", b"\x22" * 80)
                zf.write(str(xml), "5-CRC_TBX_V001.xml")
            items, sig = _prepare_transfer_items_from_path(pkg, lambda _m: None)
            self.assertIsNone(sig)
            self.assertEqual(items[0].name, "1-TBX_PART_V001.s19")
            self.assertTrue(items[1].name.endswith(".tar"))


class TestDoipPackageSelection(unittest.TestCase):
    """选文件=外层 DoIP zip（内含 s19+xml+zip 三件套）→ 解压并定位三件套。"""

    @staticmethod
    def _make_doip_package(
        root: Path, nested: bool = False, missing: str = ""
    ) -> Path:
        pkg = root / "DoIP-TBX20261127_126.zip"
        xml = _make_signature_xml(
            root, "1-TBX_E00156231_V001", "2-TBXE0015623120261127_126A01N80"
        )
        prefix = "DoIP-TBX20261127_126/" if nested else ""
        with zipfile.ZipFile(str(pkg), "w", zipfile.ZIP_DEFLATED) as zf:
            if missing != "s19":
                zf.writestr(prefix + "1-TBX_E00156231_V001.s19", b"\x11" * 43)
            if missing != "zip":
                zf.writestr(
                    prefix + "2-TBXE0015623120261127_126A01N80.zip", b"\x22" * 652
                )
            if missing != "xml":
                zf.write(str(xml), prefix + "5-CRC_TBX_V001.xml")
        return pkg

    def test_select_doip_package_zip_extracts_trio(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = self._make_doip_package(root)
            logs: list[str] = []
            items, sig = _prepare_transfer_items_from_path(pkg, logs.append)
            self.assertIsNone(sig)
            self.assertEqual(len(items), 2)
            self.assertEqual(items[0].name, "1-TBX_E00156231_V001.s19")
            self.assertEqual(items[1].name, "2-TBXE0015623120261127_126A01N80.zip")
            self.assertEqual(items[0].signature, bytes(range(256)))
            self.assertEqual(items[1].signature, bytes(reversed(range(256))))
            self.assertTrue(items[0].path.is_file())
            self.assertTrue(items[1].path.is_file())
            self.assertTrue(any("外层 DoIP 包" in m for m in logs))
            import doip_tester.flash.transfer as tr

            tmp = list(tr._EXTRACTED_TEMP_DIRS)
            self.assertEqual(len(tmp), 1)
            tr._cleanup_extracted_dirs()
            self.assertFalse(tmp[0].exists())

    def test_select_doip_package_with_nested_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = self._make_doip_package(root, nested=True)
            items, _sig = _prepare_transfer_items_from_path(pkg, lambda _m: None)
            self.assertEqual(len(items), 2)
            self.assertEqual(items[0].name, "1-TBX_E00156231_V001.s19")
            self.assertIsNotNone(items[0].signature)
            import doip_tester.flash.transfer as tr

            tr._cleanup_extracted_dirs()

    def test_doip_package_missing_trio_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pkg = self._make_doip_package(root, missing="s19")
            with self.assertRaises(ValueError):
                _prepare_transfer_items_from_path(pkg, lambda _m: None)
            import doip_tester.flash.transfer as tr

            tr._cleanup_extracted_dirs()

    def test_inner_upgrade_zip_not_treated_as_package(self) -> None:
        # 直接选内层升级包（不含三件套）→ 走同目录配对
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            s19 = root / "1-flash.s19"
            zf = root / "2-flash.zip"
            s19.write_bytes(b"\x01" * 8)
            zf.write_bytes(b"\x02" * 8)
            _make_signature_xml(root, "1-flash", "2-flash")
            items, _sig = _prepare_transfer_items_from_path(zf, lambda _m: None)
            self.assertEqual([i.name for i in items], ["1-flash.s19", "2-flash.zip"])
            self.assertEqual(items[0].path, s19)  # 未解压，直接引用原文件


class TestSignatureXmlParsing(unittest.TestCase):
    def test_parse_returns_filename_to_256byte_signature(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            xml = _make_signature_xml(root, "1-TBX_E00156231_V001", "2-TBXE0015623112")
            sig_map = parse_signature_xml(xml)
            self.assertEqual(
                list(sig_map),
                ["1-TBX_E00156231_V001", "2-TBXE0015623112"],
            )
            for v in sig_map.values():
                self.assertEqual(len(v), 256)

    def test_parse_ignores_bad_length_signature(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            xml = root / "5-CRC_TBX_V001.xml"
            xml.write_text(
                "<FileListFactory><list><fileName>a</fileName>"
                "<fileSIG>0011</fileSIG></list></FileListFactory>",
                encoding="utf-8",
            )
            self.assertEqual(parse_signature_xml(xml), {})


class TestRid0202Injection(unittest.TestCase):
    def test_0202_steps_filled_in_transfer_order(self) -> None:
        s19 = Path(tempfile.gettempdir()) / "sig_s19.tmp"
        zf = Path(tempfile.gettempdir()) / "sig_zip.tmp"
        s19.write_bytes(b"hello-s19")
        zf.write_bytes(b"hello-zip")
        try:
            items = [
                TransferItem(name="1-x.s19", path=s19, size=1, signature=bytes(range(256))),
                TransferItem(name="2-y.zip", path=zf, size=1, signature=bytes(reversed(range(256)))),
            ]
            steps = [
                RoutineStep(routine_id=0x0202, control_type=1, data=b""),
                RoutineStep(routine_id=0x0202, control_type=1, data=b""),
                RoutineStep(routine_id=0xFF00, control_type=1, data=b""),
                RoutineStep(routine_id=0xFF01, control_type=1, data=b""),
            ]
            logs: list[str] = []
            out = _inject_signatures_for_rid_0202(steps, items, logs.append)
            self.assertEqual(len(out), 4)
            self.assertEqual(out[0].data, bytes(range(256)))
            self.assertEqual(out[1].data, bytes(reversed(range(256))))
            self.assertFalse(out[2].data)
            self.assertFalse(out[3].data)
            self.assertTrue(any("RSA 签名" in m for m in logs))
        finally:
            s19.unlink(missing_ok=True)
            zf.unlink(missing_ok=True)

    def test_missing_signature_raises(self) -> None:
        s19 = Path(tempfile.gettempdir()) / "mix_s19.tmp"
        zf = Path(tempfile.gettempdir()) / "mix_zip.tmp"
        s19.write_bytes(b"hello-s19")
        zf.write_bytes(b"hello-zip")
        try:
            items = [
                TransferItem(name="1-x.s19", path=s19, size=1, signature=bytes(range(256))),
                TransferItem(name="2-y.zip", path=zf, size=1, signature=None),
            ]
            steps = [
                RoutineStep(routine_id=0x0202, control_type=1, data=b""),
                RoutineStep(routine_id=0x0202, control_type=1, data=b""),
            ]
            with self.assertRaises(RuntimeError):
                _inject_signatures_for_rid_0202(steps, items, lambda _m: None)
        finally:
            s19.unlink(missing_ok=True)
            zf.unlink(missing_ok=True)

    def test_more_0202_than_files_raises(self) -> None:
        s19 = Path(tempfile.gettempdir()) / "sig_only.tmp"
        s19.write_bytes(b"x")
        try:
            items = [
                TransferItem(name="x.s19", path=s19, size=1, signature=bytes(range(256)))
            ]
            steps = [
                RoutineStep(routine_id=0x0202, control_type=1, data=b""),
                RoutineStep(routine_id=0x0202, control_type=1, data=b""),
            ]
            with self.assertRaises(RuntimeError):
                _inject_signatures_for_rid_0202(steps, items, lambda _m: None)
        finally:
            s19.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
