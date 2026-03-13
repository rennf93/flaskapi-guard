---

title: Getting Started with FlaskAPI Guard
description: First steps guide for implementing FlaskAPI Guard security features in your Flask application
keywords: flask security tutorial, flaskapi guard setup, python security extension
---

First Steps
===========

Let's start with a simple example that shows how to add FlaskAPI Guard to your application.

Create a Flask application
----------------------------

First, create a new Flask application:

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard
from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager

app = Flask(__name__)
```

___

Configure Security Settings
----------------------------

Create a `SecurityConfig` instance with your desired settings:

```python
config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),  # NOTE: Required for geolocation
    db_path="data/ipinfo/country_asn.mmdb",  # Optional, default: ./data/ipinfo/country_asn.mmdb
    enable_redis=True,  # Enable Redis integration
    redis_url="redis://localhost:6379",  # Redis URL
    rate_limit=100,  # Max requests per minute
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    custom_log_file="security.log"  # Custom log file
)
```

Note: FlaskAPI Guard only loads resources as needed. The IPInfo database is only downloaded when country filtering is configured, and cloud IP ranges are only fetched when cloud provider blocking is enabled.

___

Add the Extension
------------------

Add the security extension to your application:

```python
FlaskAPIGuard(app, config=config)
```

___

Complete Example
----------------

Here's a complete example showing basic usage:

```python
from flask import Flask, jsonify
from flaskapi_guard import FlaskAPIGuard
from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager

app = Flask(__name__)

config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),
    enable_redis=True,  # Redis enabled
    redis_url="redis://localhost:6379",
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
    blocked_countries=["AR", "IT"],
    rate_limit=100,
    custom_log_file="security.log"
)

FlaskAPIGuard(app, config=config)

@app.route("/")
def root():
    return jsonify(message="Hello World")
```

___

Run the Application
-------------------

Run your application using gunicorn:

```bash
gunicorn main:app --reload
```

Your API is now protected by FlaskAPI Guard!

___

What's Next
-----------

- Learn about [IP Management](ip-management/banning.md)
- Configure [Rate Limiting](ip-management/rate-limiter.md)
- Set up [Penetration Detection](security/penetration-detection.md)
- Learn about [Redis Integration](redis-integration/caching.md)
