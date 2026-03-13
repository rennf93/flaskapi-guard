---

name: Bug report
about: Create a report to help us improve Flask API Guard
title: '[BUG] '
labels: bug
assignees: ''
---

Bug Description
===============

A clear and concise description of what the bug is.

___

Steps To Reproduce
------------------

Steps to reproduce the behavior:

1. Configure Flask API Guard with '...'
2. Make request to endpoint '....'
3. See error

___

Expected Behavior
-----------------

A clear and concise description of what you expected to happen.

___

Actual Behavior
---------------

What actually happened, including error messages, stack traces, or logs.

___

Environment
-----------

- Flask API Guard version: [e.g. 0.1.0]
- Python version: [e.g. 3.11.10]
- Flask version: [e.g. 3.1.0]
- OS: [e.g. Ubuntu 22.04, Windows 11, MacOS 15.4]
- Other relevant dependencies:

___

Configuration
-------------

```python
# Include your Flask API Guard configuration here
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig

app = Flask(__name__)

# Your configuration
security_config = SecurityConfig(
    # Include your config here
)

guard = FlaskAPIGuard(app, config=security_config)
```

___

Additional Context
------------------

Add any other context about the problem here. For example:

- Is this happening in production or development?
- Does it happen consistently or intermittently?
- Have you tried any workarounds?
