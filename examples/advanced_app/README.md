# FlaskAPI Guard Advanced Example

Production-ready deployment demonstrating flaskapi-guard with nginx reverse proxy, gunicorn process management, and modular project layout.

## Architecture

```
Client -> nginx (port 80) -> gunicorn (port 8000) -> Flask + guard extension
                                                                |
                                                           Redis (cache)
```

- **nginx**: Reverse proxy with rate limiting and IP forwarding headers
- **gunicorn**: Process manager with gthread workers for concurrent requests
- **flaskapi-guard**: Application-level security extension (IP filtering, penetration detection, behavioral analysis)
- **Redis**: Distributed cache for rate limiting and IP ban state

## Quick Start

```bash
cd examples/advanced_app
docker compose up --build
```

## Testing

```bash
curl http://localhost/health
curl http://localhost/basic/ip
curl http://localhost/basic/echo -X POST -H "Content-Type: application/json" -d '{"test": true}'
curl http://localhost/test/xss-test -X POST -H "Content-Type: application/json" -d '"<script>alert(1)</script>"'
for i in $(seq 1 5); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost/rate/strict-limit; done
```

## Key Differences from simple_app

| Feature | simple_app | advanced_app |
|---------|-----------|--------------|
| Reverse proxy | None | nginx with rate limiting |
| Process manager | gunicorn (dev) | gunicorn + gthread workers |
| Docker build | pip install | Multi-stage with uv |
| Runtime user | root | Non-root (guard) |
| Project layout | Single file | Modular routes + security config |
| Health checks | None | Docker health checks on all services |
| Resource limits | None | CPU and memory limits |
| Proxy trust | N/A | trusted_proxy_depth=1 |

## Configuration

Environment variables (see `.env`):

- `REDIS_URL` - Redis connection string
- `REDIS_PREFIX` - Key prefix for Redis
- `IPINFO_TOKEN` - IPInfo API token
- `WEB_CONCURRENCY` - Number of gunicorn workers
- `LOG_LEVEL` - Logging level

## Endpoints

All endpoints from simple_app are available, organized into route modules:

- `/health`, `/ready` - Health checks
- `/basic/*` - Connection test, IP info, echo
- `/access/*` - IP whitelist/blacklist, country, cloud provider filtering
- `/auth/*` - HTTPS, bearer, API key, custom headers
- `/rate/*` - Custom rate limits, geo-based rate limits
- `/behavior/*` - Usage/return monitoring, frequency detection
- `/headers/*` - CSP test, frame test, HSTS info
- `/content/*` - Bot blocking, JSON only, size limit, referrer check
- `/advanced/*` - Time windows, honeypot, suspicious pattern detection
- `/admin/*` - Ban/unban, stats, emergency mode, cloud status
- `/test/*` - XSS, SQL injection, path traversal, command injection

## Cleanup

```bash
docker compose down -v
```
