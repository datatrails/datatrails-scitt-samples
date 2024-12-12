"""
Positive test cases for verify_receipt
"""

import os
import json
import io
import unittest
import shutil
import tempfile
from contextlib import redirect_stdout

from datatrails_scitt_samples.datatrails.servicecontext import ServiceContext

from datatrails_scitt_samples.datatrails.eventpreimage import get_event
from datatrails_scitt_samples.datatrails.entryid import entryid_to_identity


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

    @unittest.skipUnless(
        os.getenv("DATATRAILS_CLIENT_SECRET") != "",
        "test requires authentication via env DATATRAILS_xxx",
    )
    def test_verify_failed_for_tampered_event(self):
        """
        registers a statement then verifies its receipt
        """
        # generate an example key
        generate_example_key(["--signing-key-file", "my-signing-key.pem"])

        # create a signed statement
        create_hashed_signed_statement(
            [
                "--signing-key-file",
                "my-signing-key.pem",
                "--payload-file",
                os.path.join(
                    self.parent_dir,
                    "datatrails_scitt_samples",
                    "artifacts",
                    "thedroid.json",
                ),
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
        output = io.StringIO()
        with redirect_stdout(output):
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

        result = json.loads(output.getvalue())
        self.assertTrue("leaf" in result)
        self.assertTrue("entryid" in result)
        self.assertTrue(os.path.exists(f"{self.test_dir}/statement-receipt.cbor"))
        self.assertTrue(os.path.exists(f"{self.test_dir}/transparent-statement.cbor"))

        entryid = result["entryid"]
        identity = entryid_to_identity(entryid)
        ctx = ServiceContext.from_env("tests")
        event = get_event(ctx, identity, True)

        event_json_file = os.path.join(self.test_dir, f"{entryid}.json")
        with open(event_json_file, "w") as file:
            file.write(json.dumps(event))

        # First verify the event as is

        # Verify the leaf value directly
        verified = False
        output = io.StringIO()
        with redirect_stdout(output):
            verified = verify_receipt(
                [
                    "--transparent-statement-file",
                    f"{self.test_dir}/transparent-statement.cbor",
                    "--event-json-file",
                    event_json_file,
                ]
            )
        self.assertEqual(output.getvalue().strip(), "verification succeeded")
        self.assertTrue(verified)

        event["event_attributes"]["test_verify_failed_for_tampered_event"] = "tampered"
        with open(event_json_file, "w") as file:
            file.write(json.dumps(event))

        output = io.StringIO()
        with redirect_stdout(output):
            verified = verify_receipt(
                [
                    "--transparent-statement-file",
                    f"{self.test_dir}/transparent-statement.cbor",
                    "--event-json-file",
                    event_json_file,
                ]
            )
        self.assertEqual(output.getvalue().strip(), "verification failed")
        self.assertFalse(verified)

    @unittest.skipUnless(
        os.getenv("DATATRAILS_CLIENT_SECRET") != "",
        "test requires authentication via env DATATRAILS_xxx",
    )
    def test_verify_transparent_statement_by_leaf(self):
        """
        registers a statement then verifies its receipt
        """
        # generate an example key
        generate_example_key(["--signing-key-file", "my-signing-key.pem"])

        # create a signed statement
        create_hashed_signed_statement(
            [
                "--signing-key-file",
                "my-signing-key.pem",
                "--payload-file",
                os.path.join(
                    self.parent_dir,
                    "datatrails_scitt_samples",
                    "artifacts",
                    "thedroid.json",
                ),
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
        output = io.StringIO()
        with redirect_stdout(output):
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

        result = json.loads(output.getvalue())
        self.assertTrue("leaf" in result)
        self.assertTrue("entryid" in result)
        self.assertTrue(os.path.exists(f"{self.test_dir}/statement-receipt.cbor"))
        self.assertTrue(os.path.exists(f"{self.test_dir}/transparent-statement.cbor"))

        # Verify the leaf value directly
        verified = False
        output = io.StringIO()
        with redirect_stdout(output):
            verified = verify_receipt(
                [
                    "--transparent-statement-file",
                    f"{self.test_dir}/transparent-statement.cbor",
                    "--leaf",
                    result["leaf"],
                ]
            )
        self.assertEqual(output.getvalue().strip(), "verification succeeded")
        self.assertTrue(verified)

    @unittest.skipUnless(
        os.getenv("DATATRAILS_CLIENT_SECRET") != "",
        "test requires authentication via env DATATRAILS_xxx",
    )
    def test_verify_transparent_statement_by_entryid(self):
        """
        registers a statement then verifies its receipt
        """
        # generate an example key
        generate_example_key(["--signing-key-file", "my-signing-key.pem"])

        # create a signed statement
        create_hashed_signed_statement(
            [
                "--signing-key-file",
                "my-signing-key.pem",
                "--payload-file",
                os.path.join(
                    self.parent_dir,
                    "datatrails_scitt_samples",
                    "artifacts",
                    "thedroid.json",
                ),
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
        output = io.StringIO()
        with redirect_stdout(output):
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

        result = json.loads(output.getvalue())
        self.assertTrue("leaf" in result)
        self.assertTrue("entryid" in result)
        self.assertTrue(os.path.exists(f"{self.test_dir}/statement-receipt.cbor"))
        self.assertTrue(os.path.exists(f"{self.test_dir}/transparent-statement.cbor"))

        # Verify the leaf value directly
        verified = False
        output = io.StringIO()
        with redirect_stdout(output):
            verified = verify_receipt(
                [
                    "--transparent-statement-file",
                    f"{self.test_dir}/transparent-statement.cbor",
                    "--entryid",
                    result["entryid"],
                ]
            )
        self.assertEqual(output.getvalue().strip(), "verification succeeded")
        self.assertTrue(verified)

    @unittest.skipUnless(
        os.getenv("DATATRAILS_CLIENT_SECRET") != "",
        "test requires authentication via env DATATRAILS_xxx",
    )
    def test_verify_receipt_by_leaf(self):
        """
        registers a statement then verifies its receipt
        """
        # generate an example key
        generate_example_key(["--signing-key-file", "my-signing-key.pem"])

        # create a signed statement
        create_hashed_signed_statement(
            [
                "--signing-key-file",
                "my-signing-key.pem",
                "--payload-file",
                os.path.join(
                    self.parent_dir,
                    "datatrails_scitt_samples",
                    "artifacts",
                    "thedroid.json",
                ),
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
        output = io.StringIO()
        with redirect_stdout(output):
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

        result = json.loads(output.getvalue())
        self.assertTrue("leaf" in result)
        self.assertTrue("entryid" in result)
        self.assertTrue(os.path.exists(f"{self.test_dir}/statement-receipt.cbor"))
        self.assertTrue(os.path.exists(f"{self.test_dir}/transparent-statement.cbor"))

        # Verify the leaf value directly
        verified = False
        output = io.StringIO()
        with redirect_stdout(output):
            verified = verify_receipt(
                [
                    "--receipt-file",
                    f"{self.test_dir}/statement-receipt.cbor",
                    "--leaf",
                    result["leaf"],
                ]
            )
        self.assertEqual(output.getvalue().strip(), "verification succeeded")
        self.assertTrue(verified)

    @unittest.skipUnless(
        os.getenv("DATATRAILS_CLIENT_SECRET") != "",
        "test requires authentication via env DATATRAILS_xxx",
    )
    def test_verify_receipt_by_entryid(self):
        """
        registers a statement then verifies its receipt
        """
        # generate an example key
        generate_example_key(["--signing-key-file", "my-signing-key.pem"])

        # create a signed statement
        create_hashed_signed_statement(
            [
                "--signing-key-file",
                "my-signing-key.pem",
                "--payload-file",
                os.path.join(
                    self.parent_dir,
                    "datatrails_scitt_samples",
                    "artifacts",
                    "thedroid.json",
                ),
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
        output = io.StringIO()
        with redirect_stdout(output):
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

        result = json.loads(output.getvalue())
        self.assertTrue("leaf" in result)
        self.assertTrue("entryid" in result)
        self.assertTrue(os.path.exists(f"{self.test_dir}/statement-receipt.cbor"))
        self.assertTrue(os.path.exists(f"{self.test_dir}/transparent-statement.cbor"))

        # Verify the leaf value directly
        verified = False
        output = io.StringIO()
        with redirect_stdout(output):
            verified = verify_receipt(
                [
                    "--receipt-file",
                    f"{self.test_dir}/statement-receipt.cbor",
                    "--entryid",
                    result["entryid"],
                ]
            )
        self.assertEqual(output.getvalue().strip(), "verification succeeded")
        self.assertTrue(verified)


if __name__ == "__main__":
    unittest.main()
