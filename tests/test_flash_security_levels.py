import unittest

from doip_tester.flash.transfer import _normalize_flash_security_levels


class TestFlashSecurityLevels(unittest.TestCase):
    def test_default_when_empty(self) -> None:
        self.assertEqual(_normalize_flash_security_levels([]), [0x01, 0x11])

    def test_only_l3_inserts_l1(self) -> None:
        self.assertEqual(_normalize_flash_security_levels([0x11]), [0x01, 0x11])

    def test_wrong_order_fixed(self) -> None:
        self.assertEqual(_normalize_flash_security_levels([0x11, 0x01]), [0x01, 0x11])

    def test_l1_only_unchanged(self) -> None:
        self.assertEqual(_normalize_flash_security_levels([0x01]), [0x01])


if __name__ == "__main__":
    unittest.main()
