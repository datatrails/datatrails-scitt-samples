from typing import List

from dataclasses import dataclass


@dataclass
class InclusionProof:
    index: int
    path: List[bytes]
