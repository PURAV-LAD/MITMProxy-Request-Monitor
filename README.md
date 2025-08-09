Request-Monitor-MITMPROXY

Install library:
pip install mitmproxy

This project allows you to capture and monitor HTTP/HTTPS requests using MITMProxy.
Files:
    cli_capture_core.py: Start with this script to understand the basics of how the capture process works.
    capture.py: Use this script to capture requests and store the logs.
    request_monitor.py: Use this script to watch the captured logs in real-time.

Instructions:
    1. Set proxy in OS Settings: 127.0.0.1:8080
    2. Run in terminal(to store the request logs): mitmproxy -s capture.py  
    3. Visit http://mitm.it/ to download certificate and store it in either browser or the OS's Certificate Manager
    4. Capture the Requests/Responses
    5. Run request_monitor.py and Click 'Start Monitoring' below to watch requests

Usage:
    Start by running cli_capture_core.py to get familiar with the capture process:
    mitmproxy -s cli_capture_core.py

    Next, run capture.py to start capturing requests and store the logs:
    mitmproxy -s capture.py
    
    Finally, run request_monitor.py to watch the captured logs in real-time:
    python request_monitor.py
