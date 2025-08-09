# Download Certificate From the http://mitm.it/ after applying proxy to localhost with port 8080  in windows proxy Setting; 127.0.0.1:8080
# mitmproxy -s cli_capture_core.py
import tkinter as tk
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    print(f"Request URL: {flow.request.url}")
    print(f"Request Headers: {flow.request.headers}")
    print(f"Request Body: {flow.request.content}")
