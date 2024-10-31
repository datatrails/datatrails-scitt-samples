"""
Generates an EXAMPLE issuer signing key using python ecdsa
"""

from ecdsa import SigningKey, NIST256p

FILE_NAME = "scitt-signing-key.pem"


def generate_key(topem=True):
    """Generate a private key using the NIST256p curve

    Provided for example and test purposes only"""
    key = SigningKey.generate(curve=NIST256p)
    if not topem:
        return key
    return key.to_pem()


def main():
    """Generate a private key and save it to a file"""
    pem_key = generate_key(topem=True)
    # Save the private key to a file
    with open(FILE_NAME, "wb") as pem_file:
        pem_file.write(pem_key)  # type: ignore
    print(f"PEM formatted private key generated and saved as '{FILE_NAME}'")


if __name__ == "__main__":
    main()
