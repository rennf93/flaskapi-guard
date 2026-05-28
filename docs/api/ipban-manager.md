---

title: IPBanManager API - FlaskAPI Guard
description: API reference for FlaskAPI Guard's IP banning system, including automatic and manual IP management
keywords: ip ban api, ban management, ip blocking api, security api
---

IPBanManager
============

The `IPBanManager` class handles temporary IP bans in your Flask application.

___

Overview
--------

```python
from flaskapi_guard import IPBanManager

ip_ban_manager = IPBanManager()
```

The `IPBanManager` uses an in-memory cache to track banned IPs and their ban durations.

___

Distributed Banning
-------------------

When Redis is enabled:

- Bans are shared across instances
- Ban expiration is handled automatically
- Supports atomic ban operations

```python
ip_ban_manager.ban_ip("192.168.1.1", 3600)

is_banned = ip_ban_manager.is_ip_banned("192.168.1.1")
```

___

Methods
-------

ban_ip
------

Ban an IP address for a specified duration.

```python
def ban_ip(ip: str, duration: int, reason: str = "threshold_exceeded") -> None
```

**Parameters**:

- `ip`: The IP address to ban
- `duration`: Ban duration in seconds
- `reason`: Reason for the ban (default: "threshold_exceeded")

**Example**:

```python
ip_ban_manager.ban_ip("192.168.1.1", 3600)  # Ban for 1 hour
```

is_ip_banned
------------

Check if an IP address is currently banned.

```python
def is_ip_banned(ip: str) -> bool
```

**Parameters**:

- `ip`: The IP address to check

**Returns**:

- `bool`: True if the IP is banned, False otherwise

**Example**:

```python
is_banned = ip_ban_manager.is_ip_banned("192.168.1.1")
```

unban_ip
--------

Remove a ban on an IP address.

```python
def unban_ip(ip: str) -> None
```

**Parameters**:

- `ip`: The IP address to unban

**Example**:

```python
ip_ban_manager.unban_ip("192.168.1.1")
```

reset
-----

Reset all banned IPs.

```python
def reset() -> None
```

**Example**:

```python
ip_ban_manager.reset()
```

___

Usage with FlaskAPIGuard
-----------------------------

The `IPBanManager` is automatically integrated when you use the `FlaskAPIGuard` extension:

```python
from flask import Flask
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard import SecurityConfig

app = Flask(__name__)

config = SecurityConfig(
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600  # Ban for 1 hour
)

FlaskAPIGuard(app, config=config)
```
