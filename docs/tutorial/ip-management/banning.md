---

title: IP Banning - FlaskAPI Guard
description: Implement automatic and manual IP banning in Flask applications using FlaskAPI Guard's IPBanManager
keywords: ip banning, ip blocking, security extension, flask security
---

IP Banning
==========

FlaskAPI Guard provides powerful IP banning capabilities through the `IPBanManager`.

___

Automatic IP Banning
---------------------

Configure automatic IP banning based on suspicious activity:

```python
config = SecurityConfig(
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600,  # Ban duration in seconds (1 hour)
)
```

___

Manual IP Banning
------------------

You can also manually ban IPs using the `IPBanManager`:

```python
from flaskapi_guard.handlers.ipban_handler import ip_ban_manager

@app.route("/admin/ban/<ip>", methods=["POST"])
def ban_ip(ip: str, duration: int = 3600):
    ip_ban_manager.ban_ip(ip, duration)
    return {"message": f"IP {ip} banned for {duration} seconds"}
```

___

Checking Ban Status
-------------------

Check if an IP is currently banned:

```python
@app.route("/admin/check/<ip>")
def check_ban(ip: str):
    is_banned = ip_ban_manager.is_ip_banned(ip)
    return {"ip": ip, "banned": is_banned}
```

___

Reset All Bans
--------------

Clear all active IP bans:

```python
@app.route("/admin/reset", methods=["POST"])
def reset_bans():
    ip_ban_manager.reset()
    return {"message": "All IP bans cleared"}
```
