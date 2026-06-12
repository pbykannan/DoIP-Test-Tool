import unittest

from doip_tester.flash.transfer import (
    _TRANSFER_DATA_FIRST_BLOCK_SEQ,
    compute_transfer_payload_size,
    next_transfer_data_block_sequence,
)


class TestFlashChunks(unittest.TestCase):
    def test_payload_from_ecu_max(self) -> None:
        self.assertEqual(compute_transfer_payload_size(4098), 4096)
        self.assertEqual(compute_transfer_payload_size(2), 1)
        self.assertEqual(compute_transfer_payload_size(3), 1)

    def test_block_sequence_wraps_ff_to_zero(self) -> None:
        self.assertEqual(next_transfer_data_block_sequence(0xFE), 0xFF)
        self.assertEqual(next_transfer_data_block_sequence(0xFF), 0x00)
        self.assertEqual(next_transfer_data_block_sequence(0x00), 0x01)

    def test_block_sequence_from_first_block(self) -> None:
        seq = _TRANSFER_DATA_FIRST_BLOCK_SEQ
        for _ in range(256):
            seq = next_transfer_data_block_sequence(seq)
        self.assertEqual(seq, 0x01)
        self.assertEqual(next_transfer_data_block_sequence(0xFF), 0x00)


if __name__ == "__main__":
    unittest.main()
