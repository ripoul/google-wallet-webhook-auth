# google-wallet-webhook-auth

Google Wallet webhook signature verification utilities for Python.

## Features

- Verify Google Wallet webhook signatures according to official documentation
- Utilities for handling Google Pay cryptographic signature formats
- Typed and tested Python code

## Installation

```bash
pip install google-wallet-webhook-auth
```

## Usage

An example with flask : 

```python
from flask import Flask, request, jsonify, abort
from google_wallet_webhook_auth import Validator
from google_wallet_webhook_auth.exceptions import SignatureVerificationError


app = Flask(__name__)

@app.route("/webhook/google/events", methods=['POST'])
def event_webhook():
    data = request.get_json()
    try:
        Validator("YOUR_ISSUER_ID").validate(data)
    except SignatureVerificationError:
        abort(401)

if __name__ == '__main__':
    app.run(debug=True)
```

## Usage with cache and django

```python
from rest_framework import permissions
from django.core.cache import cache

from google_wallet_webhook_auth import Validator
from google_wallet_webhook_auth.exceptions import SignatureVerificationError
from google_wallet_webhook_auth.cache import CacheConfig, CacheInterface

class DjangoCacheAdapter(CacheInterface):
    def get(self, key):
        return cache.get(key)

    def set(self, key, value, timeout=None):
        cache.set(key, value, timeout=timeout)

class IsGoogleWebhook(permissions.BasePermission):
    def has_permission(self, request, __view):
        cache_config = CacheConfig(key="google_key", backend=DjangoCacheAdapter())
        try:
            Validator("YOUR_ISSUER_ID", cache_config=cache_config).validate(request.data)
        except SignatureVerificationError:
            return False
        return True
```

## Development

- Install deps: `uv sync --all-extras`
- Run tests: `uv run pytest`
- Lint and format: `pre-commit run --all-files`
- Before commit: `pre-commit install`

## License

This project is licensed under the GPL-3.0-or-later. See [LICENSE](LICENSE) for details.


**Made with ❤️**
