from google_wallet_webhook_auth import Validator
from google_wallet_webhook_auth.exceptions import SignatureVerificationError
import base64
from cryptography.exceptions import InvalidSignature
from unittest.mock import MagicMock, patch
import pytest
import time
import json


def dummy_public_key():
    class DummyKey:
        def verify(self, signature, data, algo):
            if signature == base64.decodebytes(bytes("bade", "utf-8")):
                raise InvalidSignature("Invalid signature")

    return DummyKey()


@patch("google_wallet_webhook_auth.validator.construct_signed_data")
@patch("google_wallet_webhook_auth.validator.load_public_key")
@patch("google_wallet_webhook_auth.validator.requests.get")
def test_verify_intermediate_signing_key_success(
    mock_get, mock_load_key, mock_construct_signed_data
):
    mock_get.return_value.json.return_value = {"keys": [{"keyValue": "dummy"}]}
    mock_load_key.return_value = dummy_public_key()
    mock_construct_signed_data.return_value = b"data"
    data = {
        "intermediateSigningKey": {"signatures": ["good"], "signedKey": "dummy"},
        "protocolVersion": "v1",
    }
    Validator("")._verify_intermediate_signing_key(data)
    mock_get.assert_called_once()
    mock_load_key.assert_called_once_with("dummy")
    mock_construct_signed_data.assert_called_once_with("GooglePayPasses", "v1", "dummy")


@patch("google_wallet_webhook_auth.validator.construct_signed_data")
@patch("google_wallet_webhook_auth.validator.load_public_key")
@patch("google_wallet_webhook_auth.validator.requests.get")
def test_verify_intermediate_signing_key_error(
    mock_get, mock_load_key, mock_construct_signed_data
):
    mock_get.return_value.json.return_value = {"keys": [{"keyValue": "dummy"}]}
    mock_load_key.return_value = dummy_public_key()
    mock_construct_signed_data.return_value = b"data"
    data = {
        "intermediateSigningKey": {"signatures": ["bade"], "signedKey": "dummy"},
        "protocolVersion": "v1",
    }
    with pytest.raises(SignatureVerificationError):
        Validator("")._verify_intermediate_signing_key(data)
    mock_get.assert_called_once()
    mock_load_key.assert_called_once_with("dummy")
    mock_construct_signed_data.assert_called_once_with("GooglePayPasses", "v1", "dummy")


def test_validate_intermediate_signing_key_success():
    now = int(time.time() * 1000) + 10000
    data = {
        "intermediateSigningKey": {
            "signedKey": json.dumps({"keyExpiration": now, "keyValue": "dummy"})
        }
    }
    signed_key = Validator("")._validate_intermediate_signing_key(data)
    assert signed_key["keyValue"] == "dummy"


def test_validate_intermediate_signing_key_expired():
    now = int(time.time() * 1000) - 10000
    data = {
        "intermediateSigningKey": {
            "signedKey": json.dumps({"keyExpiration": now, "keyValue": "dummy"})
        }
    }
    with pytest.raises(SignatureVerificationError):
        Validator("")._validate_intermediate_signing_key(data)


@patch("google_wallet_webhook_auth.validator.construct_signed_data")
@patch("google_wallet_webhook_auth.validator.load_public_key")
def test_verify_message_signature_success(mock_load_key, mock_construct_signed_data):
    signed_key = {"keyValue": "dummy"}
    data = {
        "signature": base64.encodebytes(b"good").decode(),
        "protocolVersion": "v1",
        "signedMessage": "msg",
    }
    mock_load_key.return_value = dummy_public_key()
    mock_construct_signed_data.return_value = b"data"
    Validator("20101997")._verify_message_signature(signed_key, data)
    mock_load_key.assert_called_once_with("dummy")
    mock_construct_signed_data.assert_called_once_with(
        "GooglePayPasses", "20101997", "v1", "msg"
    )


@patch("google_wallet_webhook_auth.validator.construct_signed_data")
@patch("google_wallet_webhook_auth.validator.load_public_key")
def test_verify_message_signature_fail(mock_load_key, mock_construct_signed_data):
    signed_key = {"keyValue": "dummy"}
    data = {"signature": "bade", "protocolVersion": "v1", "signedMessage": "msg"}
    mock_load_key.return_value = dummy_public_key()
    mock_construct_signed_data.return_value = b"data"
    with pytest.raises(SignatureVerificationError):
        Validator("")._verify_message_signature(signed_key, data)


def test_verify_signature_success():
    validator = Validator("issuer_id")
    validator._verify_intermediate_signing_key = MagicMock()
    validator._validate_intermediate_signing_key = MagicMock(
        return_value={"keyValue": "dummy"}
    )
    validator._verify_message_signature = MagicMock()
    validator.validate({"dummy": "value"})
    validator._verify_intermediate_signing_key.assert_called_once_with(
        {"dummy": "value"}
    )
    validator._validate_intermediate_signing_key.assert_called_once_with(
        {"dummy": "value"}
    )
    validator._verify_message_signature.assert_called_once()


def test_verify_signature_keyerror():
    validator = Validator("issuer_id")
    validator._verify_intermediate_signing_key = MagicMock(
        side_effect=KeyError("missing")
    )
    with pytest.raises(SignatureVerificationError):
        validator.validate({"dummy": "value"})
