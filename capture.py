# capture.py 
# Run Command: mitmproxy -s capture.py
# Download Certificate From the http://mitm.it/ after applying proxy to localhost with port 8080 in windows proxy Setting; 127.0.0.1:8080

import json
import os
from datetime import datetime
from mitmproxy import http

# Log file path
LOG_FILE = "mitm_requests.log"

# Request Function
def request(flow: http.HTTPFlow) -> None:
    """Capture HTTP request and log to file"""
    try:
        # get request body
        body_content = ""
        if flow.request.content:
            try:
                body_content = flow.request.content.decode('utf-8', errors='replace')
            except:
                body_content = f"<Binary content: {len(flow.request.content)} bytes>"
        
        # To request datas format
        request_data = {
            "id": id(flow),
            "timestamp": datetime.now().isoformat(),
            "time": datetime.now().strftime("%H:%M:%S"),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "scheme": flow.request.scheme,
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "path": flow.request.path,
            "headers": dict(flow.request.headers),
            "body": body_content,
            "content_length": len(flow.request.content) if flow.request.content else 0,
            "status": None  # Will be updated in response
        }
        
        # Write into the log file declration
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(request_data) + "\n")
            f.flush()
        
        print(f"[{request_data['time']}] {request_data['method']} {request_data['url']}")
        
    except Exception as e:
        print(f"Error capturing request: {e}")

# Response Function
def response(flow: http.HTTPFlow) -> None:
    """Capture HTTP response and update the logged request"""
    try:
        # Prepare response data
        response_data = {
            "id": id(flow),
            "timestamp": datetime.now().isoformat(),
            "time": datetime.now().strftime("%H:%M:%S"),
            "status_code": flow.response.status_code,
            "reason": flow.response.reason,
            "response_headers": dict(flow.response.headers),
            "response_content_length": len(flow.response.content) if flow.response.content else 0,
            "type": "response"
        }
        
        # Write into the log file declaration
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(response_data) + "\n")
            f.flush()
        
        print(f"[{response_data['time']}] Response: {response_data['status_code']} for {flow.request.pretty_url}")
        
    except Exception as e:
        print(f"Error capturing response: {e}")

# Loader Function
def load(loader):
    """Called when the addon is loaded"""
    print("MITMProxy capture script loaded")
    print(f"Logging requests to: {os.path.abspath(LOG_FILE)}")
    
    # Clear existing data from the log file # if do not want to erase then just comment this
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    
    # Create empty log file
    with open(LOG_FILE, "w") as f:
        pass

def done():
    """Close MITMPROXY"""
    print("MITMProxy capture")
