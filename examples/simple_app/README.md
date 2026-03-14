# FlaskAPI Guard Simple Example

Single-file Flask application demonstrating all flaskapi-guard security features.

## Quick Start

```bash
docker compose up --build
```

## Testing

```bash
curl http://localhost:8000/
curl http://localhost:8000/health
curl http://localhost:8000/basic/ip
curl http://localhost:8000/basic/echo -X POST -H "Content-Type: application/json" -d '{"test": true}'
curl http://localhost:8000/test/xss-test -X POST -H "Content-Type: application/json" -d '"<script>alert(1)</script>"'
for i in $(seq 1 5); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/rate/strict-limit; done
```

## Endpoints

- `/health` - Health check (excluded from security)
- `/basic/*` - IP info, echo, health
- `/access/*` - IP whitelist/blacklist, country, cloud provider filtering
- `/auth/*` - HTTPS, bearer, API key, custom headers
- `/rate/*` - Custom rate limits, geo-based rate limits
- `/behavior/*` - Usage/return monitoring, frequency detection
- `/headers/*` - CSP test, frame test, HSTS info
- `/content/*` - Bot blocking, JSON only, size limit, referrer check
- `/advanced/*` - Time windows, honeypot, suspicious pattern detection
- `/admin/*` - Ban/unban, stats, emergency mode, cloud status
- `/test/*` - XSS, SQL injection, path traversal, command injection

## Configuration

Environment variables (see `.env`):

- `REDIS_URL` - Redis connection string
- `REDIS_PREFIX` - Key prefix for Redis
- `IPINFO_TOKEN` - IPInfo API token

## Cleanup

```bash
docker compose down -v
```
