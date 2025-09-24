# NetHub Webnettools - Python Version

A modern, Vue 3-powered web application for network testing and analysis tools, built with Python Flask and featuring an enhanced SSL checker system.

## Features

### 🔒 Enhanced SSL Checker System
- **Simple SSL Checker**: Quick, user-friendly SSL certificate validation
- **Deep SSL Analysis**: Comprehensive security testing with progress indicators
- **Client-Friendly Results**: Technical data presented in plain language
- **Multi-CDN Integration**: Highlights NetHub CDN features

### 🛠️ Network Tools
- SSL Certificate Testing (testssl.sh)
- Ping Testing
- Traceroute Analysis
- DNS Lookup (dig)
- Port Scanning (nmap)
- Network Path Analysis (mtr)

### 🎨 Modern UI/UX
- **Vue 3 Composition API**: Reactive, modern frontend
- **Bootstrap 5**: Professional, responsive design
- **Real-time Updates**: Live progress indicators and status updates
- **Mobile-First**: Responsive design for all devices

## Technology Stack

### Backend
- **Python 3.11**: Modern Python with async support
- **Flask**: Lightweight web framework
- **SSL/TLS Libraries**: Built-in Python SSL support
- **Subprocess**: Network tool execution

### Frontend
- **Vue 3**: Modern reactive framework
- **Bootstrap 5**: CSS framework
- **Bootstrap Icons**: Icon library
- **Custom CSS**: NetHub branding and animations

### Infrastructure
- **Docker**: Containerized deployment
- **Docker Compose**: Multi-service orchestration
- **Health Checks**: Automated monitoring

## Quick Start

### Using Docker (Recommended)

1. **Build and run with Docker Compose:**
```bash
cd webnettools-python
docker-compose up --build
```

2. **Access the application:**
   - Open http://localhost:8082 in your browser
   - The application will be available with all network tools

### Manual Setup

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Install system tools:**
```bash
# Ubuntu/Debian
sudo apt-get install curl dnsutils iputils-ping traceroute nmap mtr-tiny testssl.sh

# macOS
brew install curl bind iputils nmap mtr testssl.sh
```

3. **Run the application:**
```bash
python app.py
```

## API Endpoints

### SSL Certificate Check
```http
POST /api/ssl/check
Content-Type: application/json

{
  "url": "https://example.com"
}
```

### Deep SSL Analysis
```http
POST /api/ssl/deep-analysis
Content-Type: application/json

{
  "url": "https://example.com"
}
```

### Network Tools
```http
POST /api/tools/{tool_name}
Content-Type: application/json

{
  "hostname": "example.com"
}
```

Available tools: `testssl`, `ping`, `traceroute`, `dig`, `nmap`, `mtr`

## Vue 3 Components

### SSL Checker Components
- **Simple Checker**: Basic SSL validation with user-friendly results
- **Deep Analysis**: Comprehensive security testing with progress tracking
- **Results Display**: Dynamic result rendering with status indicators

### Interactive Features
- **Real-time Progress**: Animated progress bars and step indicators
- **Reactive State**: Vue 3 reactive data binding
- **Event Handling**: Click handlers and form validation
- **Dynamic UI**: Show/hide components based on state

## Configuration

### Environment Variables
- `FLASK_ENV`: Flask environment (development/production)
- `FLASK_DEBUG`: Debug mode (0/1)

### Network Tools Configuration
- `AVAILABLE_TOOLS`: List of available network tools
- `RATE_LIMIT`: Request rate limiting
- `CA_DIR`: Certificate authority directory

## Development

### Project Structure
```
webnettools-python/
├── app.py                 # Flask application
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose setup
├── templates/
│   └── index.html        # Vue 3 HTML template
├── static/
│   ├── app.js           # Vue 3 application
│   └── style.css        # Custom styles
└── README.md            # This file
```

### Adding New Tools

1. **Add tool method to `NetworkTools` class:**
```python
@staticmethod
def new_tool(hostname):
    try:
        cmd = ['new-tool', hostname]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr if result.returncode != 0 else None
        }
    except Exception as e:
        return {
            'success': False,
            'output': '',
            'error': str(e)
        }
```

2. **Add API endpoint:**
```python
@app.route('/api/tools/new-tool', methods=['POST'])
def run_new_tool():
    data = request.get_json()
    hostname = data.get('hostname', '')
    result = NetworkTools.new_tool(hostname)
    return jsonify(result)
```

3. **Add frontend component in Vue 3:**
```javascript
const newTool = ref({
    id: 'new-tool',
    icon: 'bi bi-tool',
    title: 'New Tool',
    description: 'Tool description',
    buttonText: 'Run New Tool'
});
```

## Deployment

### Production Deployment

1. **Build Docker image:**
```bash
docker build -t nethub-webnettools-python:latest .
```

2. **Run with production settings:**
```bash
docker run -d \
  --name nethub-webnettools \
  -p 8082:8080 \
  --cap-add=NET_RAW \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  nethub-webnettools-python:latest
```

### Integration with NetHub

The Python version is designed to integrate seamlessly with your NetHub platform:

- **Consistent Branding**: Matches NetHub design system
- **API Compatibility**: RESTful API endpoints
- **Docker Integration**: Easy deployment with existing infrastructure
- **Multi-CDN Features**: Highlights NetHub CDN capabilities

## Benefits of Python Version

### Advantages over Java Version
- **Simpler Development**: Python is more accessible and readable
- **Faster Iteration**: No compilation step required
- **Rich Ecosystem**: Extensive libraries for network tools
- **Better Error Handling**: More intuitive error messages
- **Easier Maintenance**: Simpler codebase structure

### Vue 3 Benefits
- **Modern Reactivity**: Better performance and developer experience
- **Composition API**: More flexible component logic
- **Better TypeScript Support**: Enhanced type safety
- **Smaller Bundle Size**: Optimized for production
- **Better DevTools**: Enhanced debugging capabilities

## Support

For issues and questions:
- **Email**: demonet2025@gmail.com
- **Company**: Infinite Scale LLC
- **Domain**: nethub.vip

## License

This project is part of the NetHub Multi-CDN Platform and is proprietary to Infinite Scale LLC.
