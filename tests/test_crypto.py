import base64
import pytest

from google_wallet_webhook_auth.crypto import construct_signed_data, load_public_key

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def test_construct_signed_data_single():
    result = construct_signed_data("abc")
    # 3 bytes, little-endian: 03 00 00 00, then b'abc'
    assert result == b"\x03\x00\x00\x00abc"


def test_construct_signed_data_multiple():
    result = construct_signed_data("foo", "bar")
    # "foo": 3 bytes, "bar": 3 bytes
    expected = b"\x03\x00\x00\x00foo\x03\x00\x00\x00bar"
    assert result == expected


def test_construct_signed_data_empty():
    result = construct_signed_data()
    assert result == b""


def generate_ec_public_key_der_base64():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii"), public_key


def test_load_public_key_valid():
    b64_der, public_key = generate_ec_public_key_der_base64()
    loaded_key = load_public_key(b64_der)
    assert loaded_key.public_numbers() == public_key.public_numbers()


def test_load_public_key_invalid():
    # Not a valid base64 string
    with pytest.raises(Exception):
        load_public_key("not-a-valid-key")
