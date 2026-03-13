FlaskAPI Guard Example App
==========================

This example demonstrates how to use FlaskAPI Guard as an extension in your Flask application.

___

Running the example
-------------------

Using Docker Compose
-------------

```bash
# Start the example app and Redis
docker compose up

# Restart
docker compose restart

# Stop
docker compose down
```

___

Available endpoints
-------------------

- `/` - Test app (various scenarios)
- `/ip` - Return client IP address
- `/test` - Test endpoint with query parameters

___

Environment variables
---------------------

- `IPINFO_TOKEN` - Token for IPInfo geolocation (required for country blocking)
- `REDIS_URL` - URL for Redis connection (default: `redis://localhost:6379`)
- `REDIS_PREFIX` - Prefix for Redis keys (default: `flaskapi_guard:`)

___

Configuration
-------------

See the configuration in `main.py` for an example of how to set up the extension with various security options.
