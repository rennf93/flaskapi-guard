---

title: Authentication Decorators - FlaskAPI Guard
description: Learn how to use authentication decorators for HTTPS enforcement, auth requirements, and API key validation
keywords: authentication, https, api keys, security headers, authorization decorators
---

Authentication Decorators
=========================

Authentication decorators provide route-level authentication and authorization controls. These decorators help ensure secure communication and proper authentication for sensitive endpoints.

___

HTTPS Enforcement
-----------------

Force secure connections for specific routes:

. Basic HTTPS Requirement
-----------------------

```python
from flaskapi_guard.decorators import SecurityDecorator

guard_deco = SecurityDecorator(config)

@app.route("/api/login", methods=["POST"])
@guard_deco.require_https()
def login():
    return {"token": "secure_jwt_token"}
```

. Combined with Global HTTPS
--------------------------

```python
# Global HTTPS enforcement
config = SecurityConfig(enforce_https=True)

# Route-specific override (still enforced due to global setting)
@app.route("/api/public")
@guard_deco.require_https()  # Explicit requirement
def public_endpoint():
    return {"data": "definitely secure"}
```

. HTTPS for Sensitive Operations
-----------------------------

```python
@app.route("/api/payment", methods=["POST"])
@guard_deco.require_https()
def payment_endpoint():
    return {"status": "payment processed securely"}

@app.route("/api/user/password", methods=["POST"])
@guard_deco.require_https()
def change_password():
    return {"status": "password updated"}
```

___

Authentication Requirements
---------------------------

Enforce different types of authentication:

. Bearer Token Authentication
--------------------------

```python
@app.route("/api/profile")
@guard_deco.require_auth(type="bearer")
def user_profile():
    return {"profile": "user data"}
```

. Multiple Authentication Types
----------------------------

```python
@app.route("/api/admin")
@guard_deco.require_auth(type="bearer")
def admin_endpoint():
    return {"admin": "data"}

@app.route("/api/service")
@guard_deco.require_auth(type="basic")
def service_endpoint():
    return {"service": "data"}
```

. Combined HTTPS and Auth
----------------------

```python
@app.route("/api/secure-admin", methods=["POST"])
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
def secure_admin():
    return {"data": "doubly secure"}
```

___

API Key Authentication
----------------------

Require API keys for endpoint access:

. Basic API Key Requirement
------------------------

```python
@app.route("/api/key-protected")
@guard_deco.api_key_auth(header_name="X-API-Key")
def api_key_endpoint():
    return {"data": "api key required"}
```

. Custom Header Names
-------------------

```python
@app.route("/api/custom-key")
@guard_deco.api_key_auth(header_name="X-Custom-Auth")
def custom_key_endpoint():
    return {"data": "custom header auth"}

@app.route("/api/service-key")
@guard_deco.api_key_auth(header_name="Authorization-Key")
def service_key_endpoint():
    return {"data": "service authentication"}
```

. Multiple Key Requirements
-------------------------

```python
@app.route("/api/dual-auth")
@guard_deco.api_key_auth(header_name="X-API-Key")
@guard_deco.api_key_auth(header_name="X-Service-Key")
def dual_auth_endpoint():
    return {"data": "dual key authentication"}
```

___

Required Headers
----------------

Enforce specific headers for authentication and security:

. Security Headers
----------------

```python
@app.route("/api/secure")
@guard_deco.require_headers({
    "X-Requested-With": "XMLHttpRequest",
    "X-CSRF-Token": "required"
})
def secure_endpoint():
    return {"data": "csrf protected"}
```

. API Versioning Headers
----------------------

```python
@app.route("/api/v2/data")
@guard_deco.require_headers({
    "Accept": "application/vnd.api+json",
    "API-Version": "2.0"
})
def versioned_endpoint():
    return {"data": "version 2.0", "format": "json-api"}
```

. Client Identification
----------------------

```python
@app.route("/api/client-specific")
@guard_deco.require_headers({
    "X-Client-ID": "required",
    "X-Client-Version": "required",
    "User-Agent": "required"
})
def client_endpoint():
    return {"data": "client identified"}
```

___

Combined Authentication Patterns
--------------------------------

Stack multiple authentication decorators for comprehensive security:

. Maximum Security Endpoint
-------------------------

```python
@app.route("/api/admin/critical", methods=["POST"])
@guard_deco.require_https()                          # Secure connection
@guard_deco.require_auth(type="bearer")              # Bearer token
@guard_deco.api_key_auth(header_name="X-Admin-Key")  # Admin API key
@guard_deco.require_headers({
    "X-CSRF-Token": "required",                      # CSRF protection
    "X-Request-ID": "required"                       # Request tracking
})
def critical_admin_endpoint():
    return {"status": "critical operation completed"}
```

. Service-to-Service Authentication
---------------------------------

```python
@app.route("/api/service/webhook", methods=["POST"])
@guard_deco.require_https()
@guard_deco.api_key_auth(header_name="X-Service-Key")
@guard_deco.require_headers({
    "X-Signature": "required",    # Webhook signature
    "Content-Type": "application/json"
})
def webhook_endpoint():
    return {"status": "webhook processed"}
```

. Client Application Authentication
---------------------------------

```python
@app.route("/api/mobile/data")
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.require_headers({
    "X-App-Version": "required",
    "X-Device-ID": "required",
    "Accept": "application/json"
})
def mobile_endpoint():
    return {"data": "mobile app data"}
```

___

Authentication Flow Examples
----------------------------

. Login Endpoint
--------------

```python
@app.route("/auth/login", methods=["POST"])
@guard_deco.require_https()
@guard_deco.require_headers({
    "Content-Type": "application/json",
    "X-CSRF-Token": "required"
})
def login():
    # Validate credentials
    return {"token": "jwt_token", "expires": "3600"}
```

. Token Refresh
-------------

```python
@app.route("/auth/refresh", methods=["POST"])
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.require_headers({
    "X-Refresh-Token": "required"
})
def refresh_token():
    return {"token": "new_jwt_token", "expires": "3600"}
```

. Logout
------

```python
@app.route("/auth/logout", methods=["POST"])
@guard_deco.require_auth(type="bearer")
@guard_deco.require_headers({
    "X-CSRF-Token": "required"
})
def logout():
    return {"status": "logged out"}
```

___

API Gateway Pattern
-------------------

Different authentication for different API tiers:

. Public API
----------

```python
@app.route("/api/public/status")
@guard_deco.api_key_auth(header_name="X-Public-Key")
def public_status():
    return {"status": "public api active"}
```

. Partner API
-----------

```python
@app.route("/api/partner/data")
@guard_deco.require_https()
@guard_deco.api_key_auth(header_name="X-Partner-Key")
@guard_deco.require_headers({
    "X-Partner-ID": "required"
})
def partner_data():
    return {"data": "partner exclusive"}
```

. Internal API
------------

```python
@app.route("/api/internal/admin")
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.api_key_auth(header_name="X-Internal-Key")
@guard_deco.require_headers({
    "X-Service-Name": "required",
    "X-Request-Context": "required"
})
def internal_admin():
    return {"data": "internal admin access"}
```

___

Error Handling
--------------

Authentication decorators return specific HTTP status codes:

- **400 Bad Request**: Missing required headers
- **401 Unauthorized**: Invalid or missing authentication
- **403 Forbidden**: Valid auth but insufficient permissions
- **301/302 Redirect**: HTTP to HTTPS redirect

. Custom Error Responses
----------------------

```python
config = SecurityConfig(
    custom_error_responses={
        400: "Missing required authentication headers",
        401: "Invalid authentication credentials",
        403: "Insufficient privileges for this operation"
    }
)
```

___

Best Practices
--------------

. Layer Authentication Methods
----------------------------

Use multiple authentication factors for sensitive operations:

```python
# Good: Multiple authentication layers
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.api_key_auth(header_name="X-API-Key")

# Avoid: Single authentication method for sensitive data
# @guard_deco.api_key_auth(header_name="X-API-Key")  # Too weak for sensitive ops
```

. Always Use HTTPS for Authentication
----------------------------------

Never transmit credentials over unencrypted connections:

```python
# Good: HTTPS enforced for login
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")

# Bad: Authentication without HTTPS
# @guard_deco.require_auth(type="bearer")  # Credentials could be intercepted
```

. Validate Header Content
-----------------------

Don't just check for presence, validate the content:

```python
# The extension handles presence validation
@guard_deco.require_headers({"X-API-Key": "required"})

# Your application code should validate the actual key value
def validate_api_key(request):
    api_key = request.headers.get("X-API-Key")
    return api_key in valid_keys
```

. Use Appropriate Authentication for Each Endpoint
----------------------------------------------

Match authentication strength to data sensitivity:

```python
# Public data: Light authentication
@guard_deco.api_key_auth(header_name="X-Public-Key")

# User data: Medium authentication
@guard_deco.require_auth(type="bearer")

# Admin data: Heavy authentication
@guard_deco.require_https()
@guard_deco.require_auth(type="bearer")
@guard_deco.api_key_auth(header_name="X-Admin-Key")
```

___

Integration with Flask Security
---------------------------------

Combine decorators with Flask's authentication utilities:

```python
from flask import request, abort
from functools import wraps

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            abort(401)
        # Validate token here
        return f(*args, **kwargs)
    return decorated

@app.route("/api/integrated")
@guard_deco.require_https()
@guard_deco.require_headers({"X-Client-ID": "required"})
@require_token
def integrated_endpoint():
    # Flask handles token extraction
    # Decorators handle additional security
    return {"data": "integrated security"}
```

___

Testing Authentication
----------------------

Test your authentication decorators:

```python
import pytest

def test_https_required(client):
    # Should redirect HTTP to HTTPS
    response = client.get("/api/secure", base_url="http://testserver")
    assert response.status_code == 301

def test_api_key_required(client):
    # Should reject without API key
    response = client.get("/api/key-protected")
    assert response.status_code == 400

    # Should accept with valid API key
    response = client.get(
        "/api/key-protected",
        headers={"X-API-Key": "valid-key"}
    )
    assert response.status_code == 200
```

___

Next Steps
----------

Now that you understand authentication decorators, explore other security features:

- **[Access Control Decorators](access-control.md)** - IP and geographic restrictions
- **[Rate Limiting Decorators](rate-limiting.md)** - Request rate controls
- **[Behavioral Analysis](behavioral.md)** - Monitor authentication patterns
- **[Content Filtering](content-filtering.md)** - Request validation

For complete API reference, see the [Authentication API Documentation](../../api/decorators.md#authenticationmixin).
