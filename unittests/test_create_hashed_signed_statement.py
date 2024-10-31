"""
Pairwise unit tests for creating a signed statement with a hashed payload
"""

import unittest
import json

from hashlib import sha256
from ecdsa import SigningKey, NIST256p

from pycose.messages import Sign1Message
from pycose.keys.curves import P256
from pycose.keys.keyparam import KpKty, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import VerifyOp
from pycose.keys import CoseKey

from scitt.statement_creation import create_hashed_signed_statement
from scitt.cbor_header_labels import (
    HEADER_LABEL_CWT,
    HEADER_LABEL_CWT_CNF,
    HEADER_LABEL_CNF_COSE_KEY,
    HEADER_LABEL_PAYLOAD_HASH_ALGORITHM,
    HEADER_LABEL_LOCATION,
)

from .constants import KNOWN_STATEMENT


class TestCreateHashedSignedStatement(unittest.TestCase):
    """
    Tests creating a signed statement with a hashed payload
    and then verifying the signature of that statement
    """

    def test_sign_and_verify_statement(self):
        """
        tests we can create a signed statement given a known key and statement.
        tests we can also verifiy that signed statement.
        """

        # create the signed statement
        signing_key = SigningKey.generate(curve=NIST256p)

        payload = json.dumps(KNOWN_STATEMENT)

        subject = "testsubject"
        issuer = "testissuer"
        content_type = "application/json"
        payload_location = "example-location"

        signed_statement = create_hashed_signed_statement(
            b"testkey",
            signing_key=signing_key,
            payload=payload,
            subject=subject,
            issuer=issuer,
            content_type=content_type,
            payload_location=payload_location,
        )

        # decode the cbor encoded cose sign1 message
        message = Sign1Message.decode(signed_statement)

        # check the returned message payload is the sha256 hash
        # and the correct headers are set
        payload_hash = sha256(payload.encode("utf-8")).digest()
        self.assertEqual(payload_hash, message.payload)
        self.assertEqual(
            -16, message.phdr[HEADER_LABEL_PAYLOAD_HASH_ALGORITHM]
        )  # -16 for sha256
        self.assertEqual(payload_location, message.phdr[HEADER_LABEL_LOCATION])

        # get the verification key from cwt cnf
        cwt = message.phdr[HEADER_LABEL_CWT]
        cnf = cwt[HEADER_LABEL_CWT_CNF]
        verification_key = cnf[HEADER_LABEL_CNF_COSE_KEY]

        cose_key_dict = {
            KpKty: KtyEC2,
            EC2KpCurve: P256,
            KpKeyOps: [VerifyOp],
            EC2KpX: verification_key[EC2KpX.identifier],
            EC2KpY: verification_key[EC2KpY.identifier],
        }

        cose_key = CoseKey.from_dict(cose_key_dict)

        message.key = cose_key

        # verify the signed statement
        verified = message.verify_signature()

        self.assertTrue(verified)
