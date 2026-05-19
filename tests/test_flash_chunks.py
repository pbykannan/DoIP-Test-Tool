import unittest

from doip_tester.flash.transfer import compute_transfer_payload_size


class TestFlashChunks(unittest.TestCase):
    def test_payload_from_ecu_max(self) -> None:
        self.assertEqual(compute_transfer_payload_size(4098), 4096)
        self.assertEqual(compute_transfer_payload_size(2), 1)
        self.assertEqual(compute_transfer_payload_size(3), 1)


if __name__ == "__main__":
    unittest.main()
