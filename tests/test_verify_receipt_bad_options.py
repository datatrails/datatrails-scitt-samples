"""
Negative test cases for verify_receipt
"""

import os
import unittest
import shutil
import tempfile

from datatrails_scitt_samples.scripts.verify_receipt import (
    main as verify_receipt,
)


class TestVerifyReciept(unittest.TestCase):
    """
    Tests verification of a known receipt.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.bad_json_file = os.path.join(self.test_dir, "bad.json")
        with open(self.bad_json_file, "w") as file:
            file.write("this is not json")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_verify_receipt_leaf_not_hex(self):
        """Cover various bad input cases"""

        # Leaf
        verified = verify_receipt(
            [
                "--transparent-statement-file",
                f"{self.test_dir}/transparent-statement.cbor",
                "--leaf",
                "this is not hex",
            ]
        )
        self.assertEqual(verified, 1)

    def test_verify_receipt_event_file_not_json(self):
        """Cover various bad input cases"""

        # Leaf
        verified = verify_receipt(
            [
                "--transparent-statement-file",
                f"{self.test_dir}/transparent-statement.cbor",
                "--event-json-file",
                self.bad_json_file,
            ]
        )
        self.assertEqual(verified, 1)

    def test_verify_receipt_bad_entryid(self):
        """Cover various bad input cases"""

        # Leaf
        verified = verify_receipt(
            [
                "--transparent-statement-file",
                f"{self.test_dir}/transparent-statement.cbor",
                "--entryid",
                "this is not found",
            ]
        )
        self.assertEqual(verified, 1)


if __name__ == "__main__":
    unittest.main()
