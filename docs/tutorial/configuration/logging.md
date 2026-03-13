---

title: Logging Configuration - FlaskAPI Guard
description: Configure security event logging and monitoring in FlaskAPI Guard with custom log formats and levels
keywords: flask logging, security logging, event monitoring, log configuration
---

Logging Configuration
=====================

FlaskAPI Guard includes powerful logging capabilities to help you monitor and track security-related events in your application.

___

Basic Logging Setup
-------------------

FlaskAPI Guard uses a hierarchical logging namespace (`flaskapi_guard`) with automatic console output and optional file logging:

```python
config = SecurityConfig(
    # Optional: Enable file logging by providing a path
    custom_log_file="security.log"  # Creates file + console output
    # OR
    # custom_log_file=None  # Console output only (default)
)
```

**Key Features:**

- Console output is **always enabled** for visibility
- File logging is **optional** and only enabled when `custom_log_file` is set
- All FlaskAPI Guard components use the `flaskapi_guard.*` namespace

___

Configurable Log Levels
------------------------

FlaskAPI Guard supports different log levels for normal and suspicious requests:

```python
config = SecurityConfig(
    # Log normal requests as INFO (or set to None to disable)
    log_request_level="INFO",
    # Log suspicious activity as WARNING
    log_suspicious_level="WARNING"
)
```

Available log levels:

- `"INFO"`: Informational messages
- `"DEBUG"`: Detailed debug information
- `"WARNING"`: Warning messages (default for suspicious activity)
- `"ERROR"`: Error conditions
- `"CRITICAL"`: Critical errors
- `None`: Disable logging completely

___

Performance Optimization
-------------------------

For high-traffic production environments, consider disabling normal request logging:

```python
config = SecurityConfig(
    # Disable normal request logging (default)
    log_request_level=None,
    # Keep security event logging enabled
    log_suspicious_level="WARNING"
)
```

___

Custom Logger
-------------

The `setup_custom_logging` function is automatically called by the extension during initialization:

```python
from flaskapi_guard.utils import setup_custom_logging

# Manual setup (if needed outside of extension)
# Console only (no file)
logger = setup_custom_logging(None)

# Console + file logging
logger = setup_custom_logging("security.log")

# The logger uses the "flaskapi_guard" namespace
# All handlers automatically use sub-namespaces like:
# - "flaskapi_guard.handlers.redis"
# - "flaskapi_guard.handlers.cloud"
# - "flaskapi_guard.handlers.ipban"
```

**Note:** The function is synchronous and handles directory creation automatically.

___

Logging
-------

FlaskAPI Guard uses a unified logging approach with the `log_activity` function that handles different types of log events:

```python
from flaskapi_guard.utils import log_activity

# Log a regular request
log_activity(request, logger)

# Log suspicious activity
log_activity(
    request,
    logger,
    log_type="suspicious",
    reason="Suspicious IP address detected"
)

# Log penetration attempt in passive mode
log_activity(
    request,
    logger,
    log_type="suspicious",
    reason="SQL injection attempt detected",
    passive_mode=True,
    trigger_info="Detected pattern: ' OR 1=1 --"
)

# Log with specific level
log_activity(
    request,
    logger,
    level="ERROR",
    reason="Authentication failure"
)
```

___

Logging Parameters
------------------

The `log_activity` function accepts the following parameters:

- `request`: The Flask request object
- `logger`: The logger instance to use
- `log_type`: Type of log entry (default: "request", can also be "suspicious")
- `reason`: Reason for flagging an activity
- `passive_mode`: Whether to format log as passive mode detection
- `trigger_info`: Details about what triggered detection
- `level`: The logging level to use. If `None`, logging is disabled. Defaults to "WARNING".

___

Logger Namespace Hierarchy
---------------------------

FlaskAPI Guard uses a hierarchical namespace structure for organized logging:

```diagram
flaskapi_guard                    # Root logger for all FlaskAPI Guard components
├── flaskapi_guard.handlers       # Handler components
│   ├── flaskapi_guard.handlers.redis
│   ├── flaskapi_guard.handlers.cloud
│   ├── flaskapi_guard.handlers.ipinfo
│   ├── flaskapi_guard.handlers.ipban
│   ├── flaskapi_guard.handlers.ratelimit
│   ├── flaskapi_guard.handlers.behavior
│   ├── flaskapi_guard.handlers.suspatterns
│   └── flaskapi_guard.handlers.dynamic_rule
├── flaskapi_guard.decorators     # Decorator components
│   └── flaskapi_guard.decorators.base
└── flaskapi_guard.detection_engine  # Detection engine components
```

This namespace isolation ensures:
- FlaskAPI Guard logs are separate from your application logs
- You can configure log levels for specific components
- Test frameworks can capture logs via propagation
- No interference with user-defined loggers

___

Log Format
----------

By default, logs include the following information:

- Timestamp
- Logger name (showing the component namespace)
- Log level
- Client IP address
- HTTP method
- Request path
- Request headers
- Request body (if available)
- Reason for logging (for suspicious activities)
- Detection trigger details (for penetration attempts)

___

Complete Examples
-----------------

Example 1: Production Setup with File Logging
----------------------------------------------

```python
from flask import Flask
from flaskapi_guard import SecurityConfig, FlaskAPIGuard

app = Flask(__name__)

# Production configuration
config = SecurityConfig(
    # File + console logging for audit trail
    custom_log_file="/var/log/flaskapi-guard/security.log",

    # Disable normal request logging to reduce noise
    log_request_level=None,

    # Keep security events at WARNING level
    log_suspicious_level="WARNING",

    # Other security settings...
    enable_redis=True,
    enable_penetration_detection=True,
)

FlaskAPIGuard(app, config=config)
```

Example 2: Development Setup with Console Only
-----------------------------------------------

```python
from flask import Flask
from flaskapi_guard import SecurityConfig, FlaskAPIGuard

app = Flask(__name__)

# Development configuration
config = SecurityConfig(
    # Console-only output for development
    custom_log_file=None,  # No file logging

    # Enable all logging for debugging
    log_request_level="INFO",
    log_suspicious_level="WARNING",

    # Other settings...
    passive_mode=True,  # Log-only mode for testing
)

FlaskAPIGuard(app, config=config)
```

Example 3: Custom Component-Level Configuration
------------------------------------------------

```python
import logging
from flaskapi_guard import SecurityConfig

# Configure specific component log levels
logging.getLogger("flaskapi_guard.handlers.redis").setLevel(logging.DEBUG)
logging.getLogger("flaskapi_guard.handlers.ipban").setLevel(logging.INFO)
logging.getLogger("flaskapi_guard.detection_engine").setLevel(logging.WARNING)

# This works because FlaskAPI Guard uses hierarchical namespaces
config = SecurityConfig(
    custom_log_file="security.log",
    # ... other settings
)
```

Example 4: Integration with Application Logging
------------------------------------------------

```python
import logging
from flask import Flask
from flaskapi_guard import SecurityConfig, FlaskAPIGuard

# Configure your application logging
app_logger = logging.getLogger("myapp")
app_logger.setLevel(logging.INFO)

# FlaskAPI Guard logs are isolated under "flaskapi_guard" namespace
# No interference with your app logs
app = Flask(__name__)

config = SecurityConfig(
    custom_log_file="security.log",  # Separate security log file
)

FlaskAPIGuard(app, config=config)

# Your app logs and FlaskAPI Guard logs remain separate
app_logger.info("Application started")  # Goes to "myapp" logger
# Security events go to "flaskapi_guard" logger
```
