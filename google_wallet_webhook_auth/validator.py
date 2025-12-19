import requests
from typing import Any
import json
import base64
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .exceptions import SignatureVerificationError
from .crypto import construct_signed_data, load_public_key
from .cache import CacheConfig


class Validator:
    issuer_id: str
    cache_config: CacheConfig | None

    def __init__(self, issuer_id: str, cache_config: CacheConfig | None = None) -> None:
        self.issuer_id = issuer_id
        self.cache_config = cache_config

    def _get_google_key(self) -> list[dict[str, Any]]:
        if self.cache_config and (
            cached_keys := self.cache_config.backend.get(self.cache_config.key)
        ):
            if isinstance(cached_keys, list):
                return cached_keys

        try:
            google_keys = requests.get(
                "https://pay.google.com/gp/m/issuer/keys", timeout=3
            ).json()
        except (requests.RequestException, json.JSONDecodeError) as e:
            raise SignatureVerificationError(
                "Could not retrieve Google root signing keys."
            ) from e

        keys = google_keys["keys"]
        assert isinstance(keys, list)
        if self.cache_config:
            self.cache_config.backend.set(self.cache_config.key, keys, timeout=86400)
        return keys

    def _verify_intermediate_signing_key(self, data: dict[str, Any]) -> None:
        """
        Verify the intermediate signing key using Google's root signing keys.

        Validates that at least one signature in the payload can be verified
        against one of Google's root signing keys.

        Args:
            data: The webhook payload containing intermediateSigningKey and signatures.

        Raises:
            SignatureVerificationError: If no valid signature is found.
        """
        signatures = [
            base64.decodebytes(bytes(s, "utf-8"))
            for s in data["intermediateSigningKey"]["signatures"]
        ]
        signed_key = data["intermediateSigningKey"]["signedKey"]
        signed_data = construct_signed_data(
            "GooglePayPasses", data["protocolVersion"], signed_key
        )

        # Check if any of the signatures are valid for any of the root signing keys
        for key in self._get_google_key():
            public_key = load_public_key(key["keyValue"])
            for signature in signatures:
                try:
                    public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
                except (ValueError, InvalidSignature):
                    # Invalid signature. Try the other signatures.
                    ...
                else:
                    # Valid signature was found
                    return
        raise SignatureVerificationError("Could not verify intermediate signing key.")

    def _validate_intermediate_signing_key(
        self, data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Validate the intermediate signing key's expiration time.

        Parses the signed key JSON and checks if the key has expired.

        Args:
            data: The webhook payload containing intermediateSigningKey.

        Returns:
            dict[str, Any]: The parsed signed key containing keyValue and keyExpiration.

        Raises:
            SignatureVerificationError: If the key has expired.
        """
        signed_key = json.loads(data["intermediateSigningKey"]["signedKey"])
        assert isinstance(signed_key, dict)
        key_expiration = signed_key["keyExpiration"]
        current_time = time.time() * 1000
        if current_time > int(key_expiration):
            raise SignatureVerificationError("Intermediate signing key has expired.")
        return signed_key

    def _verify_message_signature(
        self, signed_key: dict[str, Any], data: dict[str, Any]
    ) -> None:
        """
        Verify the message signature according to:
        https://developers.google.com/pay/api/android/guides/resources/payment-data-cryptography#verify-signature

        :raises: An exception when the message signature could not be verified.
        """
        public_key = load_public_key(signed_key["keyValue"])
        signature = base64.decodebytes(bytes(data["signature"], "utf-8"))
        signed_data = construct_signed_data(
            "GooglePayPasses",
            self.issuer_id,
            data["protocolVersion"],
            data["signedMessage"],
        )
        try:
            public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as e:
            raise SignatureVerificationError(
                "Could not verify message signature."
            ) from e

    def validate(self, payload: dict[str, Any]) -> None:
        try:
            self._verify_intermediate_signing_key(payload)
            signed_key = self._validate_intermediate_signing_key(payload)
            self._verify_message_signature(signed_key, payload)
        except KeyError as e:
            raise SignatureVerificationError("Keys or payload format error.") from e
