"""
Pairwise unit tests for creating a signed statement
"""

import unittest
import json

from base64 import b64decode

from ecdsa import SigningKey, NIST256p

from pycose.messages import Sign1Message
from pycose.keys.curves import P256
from pycose.keys.keyparam import KpKty, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import VerifyOp
from pycose.keys import CoseKey

from scitt.create_signed_statement import (
    create_signed_statement,
    HEADER_LABEL_CWT,
    HEADER_LABEL_CWT_CNF,
    HEADER_LABEL_CNF_COSE_KEY,
)

from .constants import KNOWN_STATEMENT


class TestCreateSignedStatement(unittest.TestCase):
    """
    Tests creating a signed statement and then verifying the signature of that statement
    """

    def test_sign_and_verifiy_statement(self):
        """
        tests we can create a signed statement given a known key and statement.
        tests we can also verifiy that signed statement.
        """

        # create the signed statement
        signing_key = SigningKey.generate(curve=NIST256p)

        payload = json.dumps(KNOWN_STATEMENT)

        feed = "testfeed"
        issuer = "testissuer"
        content_type = "application/json"

        signed_statement = create_signed_statement(
            signing_key, payload, feed, issuer, content_type
        )

        # verify the signed statement

        # decode the cbor encoded cose sign1 message
        message = Sign1Message.decode(signed_statement)

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
