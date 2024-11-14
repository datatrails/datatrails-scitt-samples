"""
Pairwise unit tests for creating a signed statement with a hashed payload
"""
import unittest
import json

from hashlib import sha256

import cbor2

from ecdsa import SigningKey, NIST256p

from pycose import headers
from pycose.messages import Sign1Message
from pycose.keys.curves import P256
from pycose.keys.keyparam import KpKty, EC2KpX, EC2KpY, KpKeyOps, EC2KpCurve
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyops import VerifyOp
from pycose.keys import CoseKey

from datatrails_scitt_samples.statement_creation import (
    cose_key_ec2_p256,
    create_hashed_signed_statement,
    create_hashed_statement
)

from datatrails_scitt_samples.cose_sign1message import (
    extract_to_be_signed
)

from datatrails_scitt_samples.cose_cnf_key import (
    cnf_key_from_phdr
)

from datatrails_scitt_samples.cbor_header_labels import (
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

        # XXX: TODO: Testing CI/CD infra: should still fail the Merge Requires check
        assert False is True

        # create the signed statement
        signing_key = SigningKey.generate(curve=NIST256p)

        payload_contents = json.dumps(KNOWN_STATEMENT)
        payload_hash = sha256(payload_contents.encode("utf-8")).digest()

        content_type = "application/json"
        issuer = "testissuer"
        kid = b"testkey"
        meta_map_dict = {"key1": "value", "key2": "42"}
        subject = "testsubject"
        payload_location = f"https://storage.example/{subject}"
        payload_hash_alg = "SHA-256"

        signed_statement = create_hashed_signed_statement(
            content_type=content_type,
            issuer=issuer,
            kid=kid,
            subject=subject,
            meta_map=meta_map_dict,
            payload=payload_hash,
            payload_hash_alg=payload_hash_alg,
            payload_location=payload_location,
            signing_key=signing_key,
        )

        # decode the cbor encoded cose sign1 message
        message = Sign1Message.decode(signed_statement)

        # check the returned message payload is the sha256 hash
        # and the correct headers are set
        payload_hash = sha256(payload_contents.encode("utf-8")).digest()
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


    def test_create_hashed_statement_remote_sign(self):
        """Test using the samples api to accomplish remote issuer signing"""

        # We simulate remote signing by creating a signed statement, extracting the to-0be-signed bytes,
        # and then signing explicitly and attaching the resulting signature.

        # create the signed statement
        signing_key = SigningKey.generate(curve=NIST256p)

        payload_contents = json.dumps(KNOWN_STATEMENT)
        payload_hash = sha256(payload_contents.encode("utf-8")).digest()

        content_type = "application/json"
        issuer = "testissuer"
        kid = b"testkey"
        meta_map_dict = {"key1": "value", "key2": "42"}
        subject = "testsubject"
        payload_location = f"https://storage.example/{subject}"
        payload_hash_alg = "SHA-256"

        verifying_key = signing_key.verifying_key
        self.assertIsNotNone(verifying_key)
        if verifying_key is None:
            raise ValueError("signing key does not have a verifying key")

        statement = create_hashed_statement(
            content_type=content_type,
            issuer=issuer,
            kid=kid,
            subject=subject,
            meta_map=meta_map_dict,
            payload=payload_hash,
            payload_hash_alg=payload_hash_alg,
            payload_location=payload_location,
            verifying_key=verifying_key,
        )

        # This is essentially compute_signature() from pycose's SignCommon (base of Sign1Message)
        # but without the key / alg consistency check
        to_be_signed = extract_to_be_signed(statement)

        # Send bytes to remote
        alg = statement.get_attr(headers.Algorithm)
        if alg is None:
            raise ValueError("Algorithm not set")
        cose_signing_key = CoseKey.from_dict(cose_key_ec2_p256(signing_key))
        # Receive signature bytes in response and set them on the statement
        signature = alg.sign(key=cose_signing_key, data=to_be_signed)


        # Now, locally, complete serialization of the statement with the signature attached

        # This would be nice, but pycose doesn't appear to support it
        # statement.signature = signature
        # signed_statement = statement.encode(sign=False)

        # Instead, we'll just encode directly following the implementation of encod
        struct = [statement.phdr_encoded, statement.uhdr_encoded, statement.payload, signature]
        signed_statement = cbor2.dumps(cbor2.CBORTag(statement.cbor_tag, struct), default=statement._custom_cbor_encoder)

        # decode the cbor encoded cose sign1 message
        message = Sign1Message.decode(signed_statement)

        # This method deals with some key enoding bugs in the current datatrails scitt support
        # message.key = CoseKey.from_dict(cose_key_ec2_p256(signing_key))
        message.key = CoseKey.from_dict(cnf_key_from_phdr(message.phdr))  # type: ignore

        # verify the signed statement
        verified = message.verify_signature()

        # NOTICE: This just verifies the issuer signature, not the content of
        # the statement, the counter signature by  the transparency service, or
        # its inclusion on a log.
        self.assertTrue(verified)