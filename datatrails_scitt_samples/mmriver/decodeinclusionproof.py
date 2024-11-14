"""
Support for decoding inclusion proofs defined by the MMRIVER specification.

https://www.ietf.org/archive/id/draft-bryce-cose-merkle-mountain-range-proofs-00.html

Which are a VDS tree algorithm for COSE receipts, which is defined by
https://cose-wg.github.io/draft-ietf-cose-merkle-tree-proofs/draft-ietf-cose-merkle-tree-proofs.html

"""

from typing import List

from datatrails_scitt_samples.cbor_header_labels import (
    HEADER_LABEL_COSE_RECEIPTS_VDS,
    HEADER_LABEL_COSE_RECEIPTS_VDP,
    HEADER_LABEL_COSE_RECEIPTS_INCLUSION_PROOFS,
    HEADER_LABEL_MMRIVER_INCLUSION_PROOF_INDEX,
    HEADER_LABEL_MMRIVER_INCLUSION_PROOF_PATH,
    HEADER_LABEL_MMRIVER_VDS_TREE_ALG,
)

from datatrails_scitt_samples.mmriver.inclusionproof import InclusionProof


def decode_inclusion_proofs(phdr: dict, uhdr: dict) -> List[InclusionProof]:
    """
    COSE Receipts
    Checks the headers of the mmriver receipt for the correct values
    and returns a list of inclusion proofs.
    """
    # check the receipt headers
    try:
        vds = phdr[HEADER_LABEL_COSE_RECEIPTS_VDS]
    except KeyError:
        raise KeyError("Missing COSE Receipt VDS header")

    if vds != HEADER_LABEL_MMRIVER_VDS_TREE_ALG:
        raise ValueError("COSE Receipt VDS tree algorithm is not MMRIVER")

    try:
        vds = uhdr[HEADER_LABEL_COSE_RECEIPTS_VDP]
    except KeyError:
        raise KeyError("Missing COSE Receipt VDS header")

    try:
        inclusion_proofs = vds[HEADER_LABEL_COSE_RECEIPTS_INCLUSION_PROOFS]
    except KeyError:
        raise KeyError("Missing COSE Receipt VDS inclusion proof")

    if len(inclusion_proofs) == 0:
        raise ValueError("COSE Receipt VDS inclusion proof count is not at least 1")

    proofs: List[InclusionProof] = []
    # Now check the MMRIVER specifics
    for inclusion_proof in inclusion_proofs:
        if HEADER_LABEL_MMRIVER_INCLUSION_PROOF_INDEX not in inclusion_proof:
            raise ValueError("Missing mmr-index from MMRIVER COSE Receipt of inclusion")
        if HEADER_LABEL_MMRIVER_INCLUSION_PROOF_PATH not in inclusion_proof:
            raise ValueError(
                "Missing inclusion-proof from MMRIVER COSE Receipt of inclusion"
            )

        proofs.append(
            InclusionProof(
                inclusion_proof[HEADER_LABEL_MMRIVER_INCLUSION_PROOF_INDEX],
                inclusion_proof[HEADER_LABEL_MMRIVER_INCLUSION_PROOF_PATH],
            )
        )

    return proofs
