import base64
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key


def construct_signed_data(*args: str) -> bytes:
    """
    Construct signed data according to the Google Pay signature format.

    Each argument is prefixed with its length (4 bytes, little-endian) followed
    by the UTF-8 encoded string data.

    Args:
        *args: Variable number of string arguments to include in the signed data.

    Returns:
        bytes: The constructed signed data ready for signature verification.
    """
    signed = b""
    for a in args:
        signed += len(a).to_bytes(4, byteorder="little")
        signed += bytes(a, "utf-8")
    return signed


def load_public_key(key: str) -> EllipticCurvePublicKey:
    """
    Load an elliptic curve public key from a base64-encoded DER format string.

    Args:
        key: Base64-encoded DER format public key.

    Returns:
        EllipticCurvePublicKey: The loaded public key.
    """
    derdata = base64.b64decode(key)
    return cast(EllipticCurvePublicKey, load_der_public_key(derdata))
