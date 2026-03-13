---

title: RedisManager API - FlaskAPI Guard
description: API reference for Redis-based distributed state management
keywords: redis integration, distributed state, connection pooling, atomic operations
---

RedisManager
============

The `RedisManager` class handles Redis connections and atomic operations with automatic retries.

___

Class Definition
----------------

```python
class RedisManager:
    """
    Robust Redis handler with connection pooling and automatic reconnection.
    """
```

___

Key Methods
-----------

initialize
----------

```python
def initialize(self):
    """Initialize Redis connection with retry logic"""
```

get_connection
--------------

```python
@contextmanager
def get_connection(self):
    """Context manager for safe Redis operations"""
```

safe_operation
--------------

```python
def safe_operation(self, func, *args, **kwargs):
    """Execute Redis operation with error handling"""
```

___

Atomic Operations
-----------------

get_key
-------

```python
def get_key(self, namespace: str, key: str) -> Any:
    """Get namespaced key with prefix"""
```

set_key
-------

```python
def set_key(self, namespace: str, key: str, value: Any, ttl: int | None = None) -> bool:
    """Set namespaced key with optional TTL"""
```

incr
----

```python
def incr(self, namespace: str, key: str, ttl: int | None = None) -> int:
    """Atomic increment with expiration"""
```

___

Usage Example
-------------

```python
from flaskapi_guard.handlers.redis_handler import RedisManager
from flaskapi_guard.models import SecurityConfig

config = SecurityConfig(redis_url="redis://localhost:6379")
redis = RedisManager(config)

def example():
    redis.initialize()
    with redis.get_connection() as conn:
        conn.set("test_key", "value")

    # Atomic operation
    redis.set_key("namespace", "key", "value", ttl=3600)
```
