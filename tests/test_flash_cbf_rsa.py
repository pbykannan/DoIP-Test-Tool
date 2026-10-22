import tempfile
import unittest
from pathlib import Path

from doip_tester.flash.transfer import (
    TransferItem,
    _parse_dd02_signature_from_rsa,
    _prepare_transfer_items_from_path,
)

_RSA_384_HEX = ", ".join("0x%02X" % i for i in range(384))


class TestFlashCbfRsa(unittest.TestCase):
    def test_cbf_selects_sibling_rsa(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cbf = root / "TBOX_1_1_ASW1.cbf"
            rsa = root / "TBOX_1_1_ASW1.rsa"
            cbf.write_bytes(b"\x00" * 128)
            rsa.write_text(_RSA_384_HEX, encoding="ascii")
            logs: list[str] = []
            items, sig = _prepare_transfer_items_from_path(cbf, logs.append)
            self.assertEqual(len(items), 2)
            self.assertIsInstance(items[0], TransferItem)
            self.assertEqual(items[0].name, "TBOX_1_1_ASW1.cbf")
            self.assertEqual(items[1].name, "TBOX_1_1_ASW1.rsa")
            self.assertEqual(items[0].size, 128)
            self.assertEqual(items[1].size, rsa.stat().st_size)
            self.assertIsNotNone(sig)
            assert sig is not None
            self.assertEqual(len(sig), 384)
            self.assertEqual(sig[0], 0)
            self.assertEqual(sig[-1], 0x7F)

    def test_directory_pair_picks_largest_cbf(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            small_cbf = root / "small.cbf"
            small_rsa = root / "small.rsa"
            big_cbf = root / "big.cbf"
            big_rsa = root / "big.rsa"
            small_cbf.write_bytes(b"\x01")
            small_rsa.write_text(_RSA_384_HEX, encoding="ascii")
            big_cbf.write_bytes(b"\x02" * 64)
            big_rsa.write_text(_RSA_384_HEX, encoding="ascii")
            items, _sig = _prepare_transfer_items_from_path(root, lambda _m: None)
            self.assertEqual(items[0].name, "big.cbf")
            self.assertEqual(items[1].name, "big.rsa")

    def test_missing_rsa_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            cbf = Path(td) / "only.cbf"
            cbf.write_bytes(b"\x00")
            with self.assertRaises(FileNotFoundError):
                _prepare_transfer_items_from_path(cbf, lambda _m: None)

    def test_parse_reference_rsa_length(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rsa = Path(td) / "test.rsa"
            rsa.write_text(", ".join("0x%02X" % (i & 0xFF) for i in range(384)), encoding="ascii")
            sig = _parse_dd02_signature_from_rsa(rsa)
            self.assertEqual(len(sig), 384)
            self.assertEqual(sig[0], 0x00)
            self.assertEqual(sig[255], 0xFF)

    def test_generate_dummy_rsa(self) -> None:
        from doip_tester.flash.transfer import generate_dummy_rsa
        with tempfile.TemporaryDirectory() as td:
            cbf = Path(td) / "firmware.cbf"
            cbf.write_bytes(b"\x00")
            rsa = generate_dummy_rsa(cbf)
            self.assertTrue(rsa.is_file())
            self.assertEqual(rsa.suffix, ".rsa")
            sig = _parse_dd02_signature_from_rsa(rsa)
            self.assertEqual(len(sig), 384)
            self.assertTrue(all(b == 0xFF for b in sig))


if __name__ == "__main__":
    unittest.main()
