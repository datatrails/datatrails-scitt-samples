"""Support extracting a public key from a CWT confirmation claim.

Includes a workaround for a bug in the common datatrails cose library.
"""

from pycose.keys.keyops import VerifyOp
from pycose.keys import CoseKey
from pycose.keys.curves import P384
from pycose.keys.keytype import KtyEC2
from pycose.keys.keyparam import KpKty, KpKeyOps, EC2KpCurve

from datatrails_scitt_samples.cbor_header_labels import (
    HEADER_LABEL_CWT,
    HEADER_LABEL_CWT_SCITT_DRAFT_04,
)
from datatrails_scitt_samples.cbor_header_labels import HEADER_LABEL_CWT_CNF
from datatrails_scitt_samples.cbor_header_labels import HEADER_LABEL_CNF_COSE_KEY


def cnf_key_from_phdr(phdr: dict) -> CoseKey:
    """
    Extracts the confirmation key from the cwt claims.
    """
    cwt_claims = phdr.get(HEADER_LABEL_CWT)
    if cwt_claims is None:
        # fall back to scitt draft 04
        cwt_claims = phdr.get(HEADER_LABEL_CWT_SCITT_DRAFT_04)
        if cwt_claims is None:
            raise ValueError("Missing cwt claims in protected header")

    # Note: issuer is the key vault key identity, subject is the tenant's merkle log tile path
    cnf_claim = cwt_claims.get(HEADER_LABEL_CWT_CNF)
    if not cnf_claim:
        raise ValueError("Missing confirmation claim in cwt claims")
    key = cnf_claim.get(HEADER_LABEL_CNF_COSE_KEY)
    if not key:
        raise ValueError("Missing confirmation key in cwt claims")

    key = key.copy()

    # There is a legacy "deliberate" bug in the common datatrails cose library,
    # due to a short cut for jwt compatibility.  We encode the key as 'EC', the
    # cose spec sais it MUST be 'EC2'
    if key.get(KpKty.identifier) == "EC":
        key[KpKty.identifier] = KtyEC2.identifier

    # A bug in our implementation sets key curve as 'P-384' rather than 'P_384'.
    if key[EC2KpCurve.identifier] == "P-384":
        key[EC2KpCurve.identifier] = P384.identifier

    if KpKeyOps.identifier not in key:
        key[KpKeyOps.identifier] = [VerifyOp]

    try:
        key = CoseKey.from_dict(key)
    except Exception as e:
        raise ValueError(f"Error extracting confirmation key: {e}") from e
    return key
