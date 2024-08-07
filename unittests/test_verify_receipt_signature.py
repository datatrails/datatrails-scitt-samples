"""
Known Answer Test (KAT) unit tests for verifying a receipt
"""

import unittest

from scitt.verify_receipt_signature import verify_receipt, read_cbor_file

from .constants import KNOWN_RECEIPT_FILE


class TestVerifyRecieptSignature(unittest.TestCase):
    """
    Tests verification of a known receipt.
    """

    @unittest.skip("Requires didweb which is broken")
    def test_verify_kat_receipt(self):
        """
        tests we can verify the signature of a known receipt.
        """
        receipt = read_cbor_file(KNOWN_RECEIPT_FILE)

        verified = verify_receipt(receipt)

        self.assertTrue(verified)
