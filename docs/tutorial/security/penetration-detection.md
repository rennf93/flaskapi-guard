---

title: Penetration Detection - FlaskAPI Guard
description: Detect and prevent common attack patterns including SQL injection, XSS, and other security threats
keywords: penetration detection, attack prevention, security patterns, threat detection
---

Penetration Detection
=====================

FlaskAPI Guard includes sophisticated penetration attempt detection to identify and block malicious requests.

___

Basic Configuration
-------------------

Enable penetration detection with the enhanced Detection Engine:

```python
config = SecurityConfig(
    # Core detection settings
    enable_penetration_detection=True,
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600,  # Ban duration in seconds

    # Detection Engine configuration
    detection_compiler_timeout=2.0,  # Pattern matching timeout
    detection_max_content_length=10000,  # Max content to analyze
    detection_preserve_attack_patterns=True,  # Preserve attacks during truncation
    detection_semantic_threshold=0.7,  # Semantic detection threshold (0.0-1.0)

    # Performance monitoring
    detection_anomaly_threshold=3.0,  # Standard deviations for anomaly
    detection_slow_pattern_threshold=0.1,  # Slow pattern threshold (seconds)
    detection_monitor_history_size=1000,  # Metrics history size
    detection_max_tracked_patterns=1000,  # Max patterns to track
)
```

___

Detection Patterns
------------------

The system checks for various attack patterns including:

- SQL Injection attempts
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- Template Injection
- HTTP Response Splitting
- LDAP Injection
- XML Injection
- NoSQL Injection
- File Upload attacks

___

Enhanced Detection Features
---------------------------

The new Detection Engine provides advanced threat detection capabilities:

Multi-layered Detection
-----------------------

- **Pattern Matching**: Regex-based detection with timeout protection
- **Semantic Analysis**: AI-powered detection of obfuscated attacks
- **Performance Monitoring**: Real-time tracking of pattern effectiveness

Comprehensive Results
---------------------

The detection engine returns detailed information about threats:

```python
from flaskapi_guard.handlers.suspatterns_handler import sus_patterns_handler

# Direct detection with rich results
result = sus_patterns_handler.detect(
    content="SELECT * FROM users WHERE id=1 OR 1=1",
    ip_address="192.168.1.100",
    context="query_param"
)

if result["is_threat"]:
    print(f"Threat Score: {result['threat_score']}")  # 0.0 to 1.0
    for threat in result["threats"]:
        if threat["type"] == "regex":
            print(f"Pattern: {threat['pattern']}")
        elif threat["type"] == "semantic":
            print(f"Attack Type: {threat['attack_type']}")
            print(f"Probability: {threat['probability']}")
```

Performance Analytics
---------------------

Monitor and optimize detection performance:

```python
# Get performance statistics
stats = sus_patterns_handler.get_performance_stats()
print(f"Slow patterns: {stats['slow_patterns']}")
print(f"Problematic patterns: {stats['problematic_patterns']}")
```

Custom Detection Logic
----------------------

You can use the penetration detection directly in your routes:

```python
from flaskapi_guard.utils import detect_penetration_attempt
from flask import jsonify

@app.route("/api/data", methods=["POST"])
def submit_data():
    # Legacy method (still supported)
    is_suspicious, trigger_info = detect_penetration_attempt(request)
    if is_suspicious:
        return jsonify(
            {"error": f"Suspicious activity detected: {trigger_info}"}
        ), 400
    # Process legitimate request
    return jsonify({"status": "success"})
```

For more control, use the enhanced detection API:

```python
from flaskapi_guard.handlers.suspatterns_handler import sus_patterns_handler
from flask import request, jsonify
import json

@app.route("/api/secure", methods=["POST"])
def secure_endpoint():
    data = request.get_json()
    # Check request body with enhanced detection
    result = sus_patterns_handler.detect(
        content=json.dumps(data),
        ip_address=request.remote_addr,
        context="request_body"
    )

    if result["is_threat"] and result["threat_score"] > 0.8:
        # High-confidence threat detected
        threat_types = [t.get("attack_type", t["type"]) for t in result["threats"]]
        return jsonify(
            {"error": f"Threat detected: {', '.join(threat_types)}"}
        ), 403

    # Process request
    return jsonify({"status": "success"})
```

___

Logging Suspicious Activity
----------------------------

Configure logging for suspicious activities:

```python
config = SecurityConfig(
    custom_log_file="security.log",
    log_level="WARNING"
)
```

Example log output:

```text
2024-01-20 10:15:23 - WARNING - Suspicious activity detected from 192.168.1.1: POST /api/data - Reason: SQL injection attempt
```

___

Passive Mode
------------

When `passive_mode` is enabled, FlaskAPI Guard will:

1. Detect potential penetration attempts (work as usual)
2. Log them with detailed information about what triggered the detection
3. Allow the requests to proceed without blocking

This helps you understand your traffic patterns and fine-tune your security settings before enforcing blocks that might affect legitimate users.

___

How to Use Passive Mode
-----------------------

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig

app = Flask(__name__)

# Create a configuration with passive mode enabled
config = SecurityConfig(
    enable_penetration_detection=True,  # True by default
    passive_mode=True,  # Enable passive mode
)

# Add the extension to your application
FlaskAPIGuard(app, config=config)
```

___

Checking Logs
-------------

When using passive mode, watch your logs for entries starting with "[PASSIVE MODE]". These entries provide detailed information about what triggered the detection, including:

- The client's IP address
- The HTTP method and URL
- The specific pattern that was matched
- Which part of the request triggered the detection (query parameter, body, header, etc.)
- Threat score and attack type (for semantic detection)
- Performance metrics and timeouts

___

Advanced Configuration
----------------------

Pattern Management
------------------

Add or remove custom patterns:

```python
from flaskapi_guard.handlers.suspatterns_handler import sus_patterns_handler

# Add custom pattern
sus_patterns_handler.add_pattern(
    r"(?i)exec\s*\(\s*['\"].*['\"]\s*\)",  # Detect exec() calls
    custom=True
)

# Remove pattern
sus_patterns_handler.remove_pattern(
    r"(?i)exec\s*\(\s*['\"].*['\"]\s*\)",
    custom=True
)

# Get all patterns
patterns = sus_patterns_handler.get_all_patterns()
```

Semantic Threshold Tuning
-------------------------

Adjust the semantic detection sensitivity:

```python
# More strict (fewer false positives, might miss some attacks)
sus_patterns_handler.configure_semantic_threshold(0.9)

# More lenient (catch more attacks, might have false positives)
sus_patterns_handler.configure_semantic_threshold(0.5)
```

Component Status
----------------

Check which detection components are active:

```python
status = sus_patterns_handler.get_component_status()
# Returns: {
#     "compiler": True,
#     "preprocessor": True,
#     "semantic_analyzer": True,
#     "performance_monitor": True
# }
```

___

Integration with FlaskAPI Guard Agent

When the Guard Agent is enabled, the Detection Engine automatically:

- Sends detailed threat detection events
- Reports pattern performance metrics
- Tracks pattern effectiveness
- Shares threat intelligence

Configure with:

```python
config = SecurityConfig(
    enable_agent=True,
    agent_api_key="your-api-key",
    agent_enable_events=True,
    agent_enable_metrics=True,
    # ... other settings
)
```

___

Best Practices

1. **Start with Passive Mode**: Test detection patterns without blocking traffic
2. **Monitor Performance**: Review slow patterns regularly
3. **Tune Thresholds**: Adjust based on your false positive tolerance
4. **Update Patterns**: Keep patterns updated with latest attack vectors
5. **Use Correlation IDs**: Track related detections across requests

___

Further Reading

- [Detection Engine Overview](detection-engine/overview.md)
- [Detection Engine Architecture](detection-engine/architecture.md)
- [Detection Engine Components](detection-engine/components.md)
- [Performance Tuning Guide](detection-engine/performance-tuning.md)
