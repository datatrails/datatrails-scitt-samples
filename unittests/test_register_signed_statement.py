"""Tests end to end creation, registration, and verification of a signed statement

***
Requires the following environment:
***

DATATRAILS_URL url to instance (prod default)
DATATRAILS_CLIENT_ID client id for custom integration on the instance
DATATRAILS_CLIENT_SECRET client secret for custom integration on the instance
"""

import os
import shutil
import tempfile
import unittest

from datatrails_scitt_samples.scripts.generate_example_key import main as generate_example_key
from datatrails_scitt_samples.scripts.create_hashed_signed_statement import (
    main as create_hashed_signed_statement,
)
from datatrails_scitt_samples.scripts.register_signed_statement import main as register_signed_statement


class TestRegisterSignedStatement(unittest.TestCase):
    """End to end system test for SCITT statement registration and verification"""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    @unittest.skipUnless(
        os.getenv("DATATRAILS_CLIENT_SECRET") != "",
        "test requires authentication via env DATATRAILS_xxx",
    )
    def test_create_and_register_statement(self):
        """Test creating a signed statement and registering it"""

        # generate an example key
        generate_example_key(
            ["--signing-key-file", f"{self.test_dir}/scitt-signing-key.pem"]
        )

        # create a signed statement
        create_hashed_signed_statement(
            [
                "--signing-key-file",
                f"{self.test_dir}/scitt-signing-key.pem",
                "--payload-file",
                os.path.join(self.parent_dir, "datatrails_scitt_samples", "artifacts", "thedroid.json"),
                "--content-type",
                "application/json",
                "--subject",
                "TestRegisterSignedStatement:test_create_and_register_statement",
                "--issuer",
                "https://github.com/datatrails/datatrails-scitt-samples",
                "--output-file",
                f"{self.test_dir}/signed-statement.cbor",
            ]
        )
        self.assertTrue(os.path.exists(f"{self.test_dir}/signed-statement.cbor"))

        # register the signed statement
        register_signed_statement(
            [
                "--signed-statement-file",
                f"{self.test_dir}/signed-statement.cbor",
                "--output-file",
                f"{self.test_dir}/transparent-statement.cbor",
                "--output-receipt-file",
                f"{self.test_dir}/statement-receipt.cbor",
            ]
        )
        self.assertTrue(os.path.exists(f"{self.test_dir}/statement-receipt.cbor"))
        self.assertTrue(os.path.exists(f"{self.test_dir}/transparent-statement.cbor"))

        # Note: requesting the transparent statement forces verification of the
        # signed statement receipt  before it is attached.


if __name__ == "__main__":
    unittest.main()
