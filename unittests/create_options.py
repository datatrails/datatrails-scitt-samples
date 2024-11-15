from datatrails_scitt_samples.statement_creation import OPTION_USE_DRAFT_04_LABELS
from datatrails_scitt_samples.cbor_header_labels import (
    HEADER_LABEL_CWT,
    HEADER_LABEL_CWT_SCITT_DRAFT_04,
)

# Use this until the backend support for cwt label 15 is available
create_options = {OPTION_USE_DRAFT_04_LABELS: True}


def get_cwt_phdr(phdr):
    return phdr.get(HEADER_LABEL_CWT) or phdr.get(HEADER_LABEL_CWT_SCITT_DRAFT_04)
