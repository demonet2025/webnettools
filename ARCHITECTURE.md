# NetHub Webnettools - Technical Architecture

## System Architecture Overview

### High-Level Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Web Server    │    │   Application   │
│     (Nginx)     │────│   (Nginx)       │────│   (Flask)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                       ┌─────────────────┐            │
                       │   Monitoring    │            │
                       │ (VictoriaMetrics│            │
                       │   + Grafana)    │            │
                       └─────────────────┘            │
                                                       │
                       ┌─────────────────┐            │
                       │   Background    │            │
                       │   Tasks (Celery)│            │
                       └─────────────────┘            │
                                                       │
                       ┌─────────────────┐            │
                       │   Cache (Redis) │────────────┘
                       └─────────────────┘
```

## 1. Frontend Architecture

### 1.1 Template System

#### Base Template Structure
```html
<!-- base.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Meta tags, CSS, structured data -->
    {% block title %}{% endblock %}
    {% block meta_description %}{% endblock %}
    {% block meta_keywords %}{% endblock %}
</head>
<body>
    <!-- Unified header with navigation -->
    <nav class="navbar">...</nav>
    
    <!-- Main content area -->
    <main>
        {% block content %}{% endblock %}
    </main>
    
    <!-- Unified footer -->
    <footer>...</footer>
    
    <!-- JavaScript -->
    {% block scripts %}{% endblock %}
</body>
</html>
```

#### Tool Page Template Pattern
```html
<!-- [tool].html -->
{% extends "base.html" %}

{% block title %}Tool Name - NetHub Network Tools{% endblock %}
{% block meta_description %}Tool description...{% endblock %}
{% block meta_keywords %}tool, keywords{% endblock %}

{% block content %}
<div class="container mt-5 pt-4">
    <!-- Tool-specific content -->
    <div class="card">
        <!-- Tool form and results -->
    </div>
</div>
{% endblock %}

{% block scripts %}
<script src="/static/[tool]-app.js"></script>
{% endblock %}
```

### 1.2 Vue.js Application Structure

#### Component Architecture
```javascript
// [tool]-app.js
const { createApp, ref, reactive } = Vue;

createApp({
    setup() {
        // Reactive state
        const formData = ref({});
        const results = ref(null);
        const isLoading = ref(false);
        const errorMessage = ref('');
        
        // Methods
        const submitForm = async () => {
            // API call logic
        };
        
        return {
            formData,
            results,
            isLoading,
            errorMessage,
            submitForm
        };
    }
}).mount('#app');
```

### 1.3 CSS Architecture

#### Bootstrap Integration
- **Bootstrap 5.3.0**: Primary CSS framework
- **Custom CSS**: `style.css` for project-specific styles
- **Responsive Design**: Mobile-first approach
- **Component Styling**: Consistent component styling across tools

#### CSS Organization
```css
/* style.css */
:root {
    --primary-color: #0d6efd;
    --secondary-color: #6c757d;
    --success-color: #198754;
    --danger-color: #dc3545;
    --warning-color: #ffc107;
    --info-color: #0dcaf0;
}

/* Component styles */
.tool-card { /* ... */ }
.result-section { /* ... */ }
.loading-spinner { /* ... */ }
```

## 2. Backend Architecture

### 2.1 Flask Application Structure

#### Main Application (app.py)
```python
from flask import Flask, render_template, request, jsonify
from modules.ssl_analyzer import SSLAnalyzer
from modules.network_tools import NetworkTools
from modules.decode_encoder import DecodeEncoder
from modules.subnet_calculator import SubnetCalculator

app = Flask(__name__)

# Routes
@app.route('/')
def index():
    return render_template('homepage.html')

@app.route('/api/ssl/check', methods=['POST'])
def ssl_check():
    # SSL check API endpoint
    pass

# Additional routes...
```

#### Modular Backend Components

##### SSL Analyzer Module
```python
# modules/ssl_analyzer.py
class SSLAnalyzer:
    def check_ssl_certificate(self, url):
        """Basic SSL certificate validation"""
        pass
    
    def analyze_ssl_security(self, url):
        """Deep SSL security analysis"""
        pass

class CSRDecoder:
    def decode_csr(self, csr_data):
        """Decode Certificate Signing Request"""
        pass
```

##### Network Tools Module
```python
# modules/network_tools.py
class NetworkTools:
    def ping_host(self, hostname, count=4):
        """Ping a host and return results"""
        pass
    
    def trace_route(self, hostname, max_hops=30):
        """Perform traceroute analysis"""
        pass
    
    def dns_lookup(self, domain, record_type='A'):
        """Perform DNS lookup"""
        pass
```

### 2.2 API Design

#### RESTful API Endpoints
```python
# SSL Tools
POST /api/ssl/check              # Basic SSL check
POST /api/ssl/deep-check         # Deep SSL analysis
POST /api/ssl/csr-decode         # CSR decoding

# Network Tools
POST /api/network/ping           # Ping test
POST /api/network/traceroute     # Traceroute
POST /api/network/dig            # DNS lookup

# Utility Tools
POST /api/encode/base64          # Base64 encoding
POST /api/encode/url             # URL encoding
POST /api/subnet/ipv4            # IPv4 subnet calculation
```

#### Response Format
```json
{
    "success": true,
    "data": {
        "result": "tool-specific data",
        "timestamp": "2025-01-24T17:00:00Z",
        "execution_time": 1.23
    },
    "error": null
}
```

### 2.3 Error Handling

#### Error Response Format
```json
{
    "success": false,
    "data": null,
    "error": {
        "code": "INVALID_INPUT",
        "message": "Invalid hostname provided",
        "details": "Hostname must be a valid domain or IP address"
    }
}
```

#### Error Categories
- **Validation Errors**: Input validation failures
- **Network Errors**: Network connectivity issues
- **Tool Errors**: External tool execution failures
- **System Errors**: Internal system failures

## 3. Database Architecture

### 3.1 Data Storage Strategy

#### No Persistent Data Storage
- **Stateless Design**: No user data persistence
- **Session Management**: Redis for temporary session data
- **Cache Storage**: Redis for API response caching
- **Log Storage**: Structured logging without user data

#### Future Database Schema (if needed)
```sql
-- Users table (future enhancement)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tool usage logs (future enhancement)
CREATE TABLE tool_usage (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    tool_name VARCHAR(100) NOT NULL,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 4. Security Architecture

### 4.1 Input Validation

#### Validation Pipeline
```python
def validate_input(data, schema):
    """Validate input data against schema"""
    try:
        # Sanitize input
        sanitized = sanitize_input(data)
        
        # Validate against schema
        validated = schema.validate(sanitized)
        
        return validated
    except ValidationError as e:
        raise InvalidInputError(str(e))
```

#### Input Sanitization
```python
def sanitize_input(data):
    """Sanitize user input to prevent injection attacks"""
    if isinstance(data, str):
        # Remove potentially dangerous characters
        data = re.sub(r'[;&|`$]', '', data)
        # Limit length
        data = data[:1000]
    return data
```

### 4.2 Network Security

#### Command Execution Safety
```python
def safe_execute_command(command, args):
    """Safely execute system commands"""
    # Validate command against whitelist
    if command not in ALLOWED_COMMANDS:
        raise SecurityError("Command not allowed")
    
    # Limit arguments
    if len(args) > MAX_ARGS:
        raise SecurityError("Too many arguments")
    
    # Execute with timeout
    return subprocess.run(
        [command] + args,
        timeout=30,
        capture_output=True,
        text=True
    )
```

## 5. Performance Architecture

### 5.1 Caching Strategy

#### Multi-Level Caching
```python
# Redis caching for API responses
@cache.memoize(timeout=300)  # 5 minutes
def get_ssl_certificate_info(url):
    """Cache SSL certificate information"""
    pass

# Browser caching for static assets
# Cache-Control: max-age=31536000 (1 year)
```

#### Cache Invalidation
```python
def invalidate_cache(pattern):
    """Invalidate cache entries matching pattern"""
    cache.delete_memoized_verhash()
```

### 5.2 Asynchronous Processing

#### Background Tasks
```python
from celery import Celery

celery = Celery('webnettools')

@celery.task
def long_running_analysis(url):
    """Background task for long-running analysis"""
    pass
```

#### Real-time Updates
```python
def stream_analysis_results(task_id):
    """Stream analysis results to client"""
    def generate():
        while not task.ready():
            yield f"data: {task.info}\n\n"
            time.sleep(1)
    
    return Response(generate(), mimetype='text/event-stream')
```

## 6. Monitoring Architecture

### 6.1 Application Monitoring

#### Metrics Collection
```python
from prometheus_client import Counter, Histogram, Gauge

# Custom metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')
ACTIVE_CONNECTIONS = Gauge('active_connections', 'Active connections')
```

#### Health Checks
```python
@app.route('/health')
def health_check():
    """Application health check endpoint"""
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0'
    }
```

### 6.2 Infrastructure Monitoring

#### VictoriaMetrics Integration
```yaml
# victoriametrics.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'webnettools'
    static_configs:
      - targets: ['webnettools:8080']
    metrics_path: '/metrics'
```

#### Grafana Dashboards
- **Application Metrics**: Request rates, response times, error rates
- **System Metrics**: CPU, memory, disk usage
- **Business Metrics**: Tool usage, user engagement

## 7. Deployment Architecture

### 7.1 Container Architecture

#### Docker Configuration
```dockerfile
# Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl dnsutils iputils-ping traceroute nmap mtr-tiny testssl.sh \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . /app
WORKDIR /app

# Expose port
EXPOSE 8080

# Start application
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
```

#### Docker Compose Services
```yaml
# docker-compose.dev.yml
services:
  webnettools:
    build: ./webnettools-python
    ports:
      - "8082:8080"
    environment:
      - FLASK_ENV=development
    volumes:
      - ./webnettools-python:/app
    networks:
      - gaius-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - gaius-network

  victoriametrics:
    image: victoriametrics/victoria-metrics:latest
    ports:
      - "8428:8428"
    networks:
      - gaius-network
```

### 7.2 Production Deployment

#### Nginx Configuration
```nginx
# nginx.conf
server {
    listen 80;
    server_name tools.nethub.vip;
    
    location / {
        proxy_pass http://webnettools:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    location /static/ {
        alias /app/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

#### SSL/TLS Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name tools.nethub.vip;
    
    ssl_certificate /etc/letsencrypt/live/tools.nethub.vip/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tools.nethub.vip/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
}
```

## 8. Development Workflow

### 8.1 Local Development

#### Development Setup
```bash
# Clone repository
git clone https://github.com/nethub/webnettools.git
cd webnettools

# Start development environment
docker-compose -f docker-compose.dev.yml up -d

# Access application
open http://localhost:8082
```

#### Code Quality Tools
```bash
# Linting
flake8 webnettools-python/
black webnettools-python/

# Type checking
mypy webnettools-python/

# Testing
pytest webnettools-python/tests/
```

### 8.2 CI/CD Pipeline

#### GitHub Actions Workflow
```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: pytest
      - name: Run linting
        run: flake8 webnettools-python/
```

## 9. Scalability Considerations

### 9.1 Horizontal Scaling

#### Load Balancing
- **Nginx Load Balancer**: Distribute traffic across multiple instances
- **Health Checks**: Monitor instance health and remove unhealthy instances
- **Session Affinity**: Sticky sessions for real-time features

#### Auto-scaling
- **Container Orchestration**: Kubernetes or Docker Swarm
- **Metrics-based Scaling**: Scale based on CPU, memory, and request metrics
- **Predictive Scaling**: Scale based on usage patterns

### 9.2 Performance Optimization

#### Database Optimization
- **Connection Pooling**: Efficient database connection management
- **Query Optimization**: Optimized database queries
- **Indexing Strategy**: Proper database indexing

#### Caching Optimization
- **CDN Integration**: Global content delivery
- **Edge Caching**: Cache at edge locations
- **Cache Warming**: Pre-populate frequently accessed data

---

**Document Version**: 1.0  
**Last Updated**: January 2025  
**Next Review**: March 2025  
**Maintained By**: Development Team
