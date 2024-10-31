"""
Known Answer Test (KAT) unit tests for verifying a receipt
"""

import unittest

from scitt.cose_receipt_verification import verify_receipt_mmriver

from .constants import KNOWN_RECEIPT_FILE

from scitt.scripts.fileaccess import read_cbor_file


class TestVerifyReciept(unittest.TestCase):
    """
    Tests verification of a known receipt.
    """

    @unittest.skip("Requires knowing the leaf hash")
    def test_verify_kat_receipt(self):
        """
        tests we can verify the signature of a known receipt.
        """
        receipt = read_cbor_file(KNOWN_RECEIPT_FILE)
        verified = verify_receipt_mmriver(receipt, b"will fail until leaf hash is known")

        self.assertTrue(verified)
