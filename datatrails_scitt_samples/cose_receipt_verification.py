"""Verification of the MMRIVER draft-bryce-cose-merkle-mountain-range-proofs receipt"""

from pycose.messages import Sign1Message
from datatrails_scitt_samples.cose_sign1message import decode_sign1_detached
from datatrails_scitt_samples.cose_cnf_key import cnf_key_from_phdr
from datatrails_scitt_samples.mmriver.decodeinclusionproof import (
    decode_inclusion_proofs,
)
from datatrails_scitt_samples.mmriver.algorithms import included_root


def verify_receipt_mmriver(receipt: bytes, leaf: bytes) -> bool:
    """
    Verifies the counter signed receipt signature
    Args:
        receipt: COSE Receipt as cbor encoded bytes
        leaf: append only log leaf hash proven by the receipt. provided as bytes
    """

    message: Sign1Message = decode_sign1_detached(receipt)

    # While many proofs may be supplied, only the first is used here.  The
    # checks will raise unless there is at least one proof found.  Note that
    # when the proof is None it means the inclusion path is empty and the leaf
    # is the payload of the receipt.  (And is also a direct member of the
    # accumulator)
    proof = decode_inclusion_proofs(message.phdr, message.uhdr)[0]
    path = proof.path or []

    root = included_root(proof.index, leaf, path)
    message.payload = root

    # Extract the signing key from the cwt claims in the protected header
    # The receipt signing key is the merklelog consistency checkpoint siging key.
    # Which is declared publicly in many places including the DataTrails web ui.
    # Note that this is *not* the same as the signed statement counter signing key.

    signing_key = cnf_key_from_phdr(message.phdr)
    message.key = signing_key
    # pylint: disable=no-member
    return message.verify_signature()  # type: ignore
