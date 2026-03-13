---

title: Custom Security Patterns - FlaskAPI Guard
description: Create and manage custom security patterns for detecting specific threats in your Flask application
keywords: security patterns, custom detection, threat patterns, security rules
---

Custom Patterns
===============

FlaskAPI Guard allows you to add custom patterns for detecting suspicious activity.

___

Adding Custom Patterns
-----------------------

Add your own patterns to the detection system:

```python
from flaskapi_guard.handlers.suspatterns_handler import SusPatternsManager

def setup_patterns():
    # Add custom pattern
    SusPatternsManager.add_pattern(
        r"malicious_pattern.*",
        custom=True
    )
```

___

Pattern Types
-------------

You can add patterns for different types of attacks:

```python
# Custom XSS pattern
SusPatternsManager.add_pattern(
    r"<script\s*src=.*>",
    custom=True
)

# Custom SQL injection pattern
SusPatternsManager.add_pattern(
    r";\s*DROP\s+TABLE",
    custom=True
)

# Custom file path pattern
SusPatternsManager.add_pattern(
    r"\.\.\/.*\/etc\/passwd",
    custom=True
)
```

___

Managing Patterns
-----------------

Remove or modify existing patterns:

```python
# Remove a custom pattern
success = SusPatternsManager.remove_pattern(
    r"malicious_pattern.*",
    custom=True
)
if success:
    print("Pattern removed successfully")
else:
    print("Pattern not found")

# Get all patterns (both default and custom)
all_patterns = SusPatternsManager.get_all_patterns()

# Get only default patterns
default_patterns = SusPatternsManager.get_default_patterns()

# Get only custom patterns
custom_patterns = SusPatternsManager.get_custom_patterns()

# Get all compiled patterns
all_compiled_patterns = SusPatternsManager.get_all_compiled_patterns()

# Get only default compiled patterns
default_compiled = SusPatternsManager.get_default_compiled_patterns()

# Get only custom compiled patterns
custom_compiled = SusPatternsManager.get_custom_compiled_patterns()
```

___

Pattern Testing
---------------

Test your patterns against requests:

```python
from flaskapi_guard.utils import detect_penetration_attempt
from flask import request, jsonify

@app.route("/test/patterns", methods=["POST"])
def test_patterns():
    is_suspicious, trigger_info = detect_penetration_attempt(request)
    return jsonify({
        "suspicious": is_suspicious,
        "trigger_info": trigger_info,
        "request_body": request.get_data(as_text=True)
    })
```
