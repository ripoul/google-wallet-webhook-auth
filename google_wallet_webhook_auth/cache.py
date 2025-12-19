from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Any


class CacheInterface(ABC):
    """Abstract interface for a simple key/value cache backend.
    Implementations are responsible for providing storage and retrieval
    of arbitrary Python objects associated with string keys.
    """

    @abstractmethod
    def get(self, key: str) -> Any:
        """Retrieve a value from the cache by key.
        Args:
            key: The string key whose value should be retrieved.
        Returns:
            The cached value associated with ``key`` if it exists and has
            not expired. Implementations should return ``None`` when the
            key is not present or the entry has expired.
        """
        ...

    @abstractmethod
    def set(self, key: str, value: Any, timeout: int | None = None) -> None:
        """Store a value in the cache under the given key.
        Args:
            key: The string key under which the value should be stored.
            value: The value to cache. This may be any serializable object
                supported by the backend implementation.
            timeout: The cache lifetime in seconds. If ``None``, the
                backend's default timeout should be used, which may mean
                that the value does not expire automatically.
        """
        ...


@dataclass
class CacheConfig:
    """Configuration for caching Google's public keys used for webhook verification.
    This dataclass groups together the cache key and the cache backend implementation.
    """

    key: str
    """Cache key under which Google's public keys will be stored."""
    backend: CacheInterface
    """Cache backend used to store and retrieve Google's public keys.
    This should be an implementation of :class:`CacheInterface`.
    """
