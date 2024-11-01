"""Definitions of all COSE, SCITT, CBOR labels used by these exmaples """

# CWT header label comes from version 4 of the scitt architecture document
# https://www.ietf.org/archive/id/draft-ietf-scitt-architecture-04.html#name-issuer-identity
HEADER_LABEL_CWT = 13

# subject header label comes from version 2 of the scitt architecture document
# https://www.ietf.org/archive/id/draft-birkholz-scitt-architecture-02.html#name-envelope-and-claim-format
HEADER_LABEL_FEED = 392

# Various CWT header labels come from:
# https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1
HEADER_LABEL_CWT_ISSUER = 1
HEADER_LABEL_CWT_SUBJECT = 2

# CWT CNF header labels come from:
# https://datatracker.ietf.org/doc/html/rfc8747#name-confirmation-claim
HEADER_LABEL_CWT_CNF = 8
HEADER_LABEL_CNF_COSE_KEY = 1

# Signed Hash envelope header labels from:
# https://github.com/OR13/draft-steele-cose-hash-envelope/blob/main/draft-steele-cose-hash-envelope.md
# pre-adoption/private use parameters
# https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
HEADER_LABEL_PAYLOAD_HASH_ALGORITHM = -6800
HEADER_LABEL_LOCATION = -6801
HEADER_LABEL_PAYLOAD_PRE_CONTENT_TYPE = -6802

# meta-map from:
# https://github.com/SteveLasker/cose-meta-map
# key/value pairs of tstr:tstr supporting metadata
# pre-adoption/private use parameters
# https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
HEADER_LABEL_META_MAP = -6804

# CBOR Object Signing and Encryption (COSE) "typ" (type) Header Parameter
# https://datatracker.ietf.org/doc/rfc9596/
HEADER_LABEL_TYPE = 16
COSE_TYPE = "application/hashed+cose"

# COSE Receipts headers
# https://cose-wg.github.io/draft-ietf-cose-merkle-tree-proofs/draft-ietf-cose-merkle-tree-proofs.html#name-new-entries-to-the-cose-hea
HEADER_LABEL_DID = 391
HEADER_LABEL_COSE_RECEIPTS_VDS = 395
HEADER_LABEL_COSE_RECEIPTS_VDP = 396
HEADER_LABEL_COSE_RECEIPTS_INCLUSION_PROOFS = -1

# MMRIVER headers
# https://robinbryce.github.io/draft-bryce-cose-merkle-mountain-range-proofs/draft-bryce-cose-merkle-mountain-range-proofs.html#name-receipt-of-inclusion
HEADER_LABEL_MMRIVER_VDS_TREE_ALG = 2
HEADER_LABEL_MMRIVER_INCLUSION_PROOF_INDEX = 1
HEADER_LABEL_MMRIVER_INCLUSION_PROOF_PATH = 2

# https://datatracker.ietf.org/doc/html/rfc8747#name-confirmation-claim
HEADER_LABEL_CWT_CNF = 8
HEADER_LABEL_CNF_COSE_KEY = 1
HEADER_LABEL_COSE_ALG_SHA256 = -16
HEADER_LABEL_COSE_ALG_SHA384 = -43
HEADER_LABEL_COSE_ALG_SHA512 = -44
HEADER_LABEL_COSE_ALG_SHA512_256 = -17
