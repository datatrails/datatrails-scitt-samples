"""
Negative test cases for verify_receipt
"""

import os
import json
import io
import unittest
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout

from datatrails_scitt_samples.scripts.generate_example_key import (
    main as generate_example_key,
)
from datatrails_scitt_samples.scripts.create_hashed_signed_statement import (
    main as create_hashed_signed_statement,
)
from datatrails_scitt_samples.scripts.register_signed_statement import (
    main as register_signed_statement,
)
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
        self.assertFalse(verified)

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
        self.assertFalse(verified)

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
        self.assertFalse(verified)


if __name__ == "__main__":
    unittest.main()
