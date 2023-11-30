"""
Known Answer Test (KAT) unit tests for verifying a receipt
"""

import unittest

from scitt.verify_receipt_signature import verify_receipt

from .constants import KNOWN_RECEIPT


class TestVerifyRecieptSignature(unittest.TestCase):
    """
    Tests verification of a known receipt.
    """

    def test_verify_kat_receipt(self):
        """
        tests we can verify the signature of a known receipt.
        """

        verified = verify_receipt(KNOWN_RECEIPT)

        self.assertTrue(verified)
