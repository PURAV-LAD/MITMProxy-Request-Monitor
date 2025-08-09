# After Capturing the requestes,response logs start this code to check those logs
# Run Command: python request_monitor.py

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import json
import os
import time
from datetime import datetime

class MITMProxyUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MITMProxy Request Monitor")
        self.root.geometry("1400x900")
        
        # Log file path
        self.log_file = "mitm_requests.log"
        self.last_position = 0
        
        # Queue for thread
        self.request_queue = queue.Queue()
        
        # main frame
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Info frame
        info_frame = ttk.LabelFrame(main_frame, text="Instructions", padding="10")
        info_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        instructions = """1. Set proxy in Windows Settings: 127.0.0.1:8080
2. Run in terminal: mitmproxy -s capture.py
3. Visit http://mitm.it/ to download certificate and store it
4. Capture the Requests/Responses
5. Run request_monitor.py and Click 'Start Monitoring' below to watch requests"""
        
        ttk.Label(info_frame, text=instructions, font=("Arial", 9)).pack(anchor=tk.W)
        
        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.monitor_button = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.monitor_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(control_frame, text="Clear Log", command=self.clear_log)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.refresh_button = ttk.Button(control_frame, text="Refresh", command=self.refresh_requests)
        self.refresh_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Status and counter
        self.status_label = ttk.Label(control_frame, text="Status: Not Monitoring", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=(20, 10))
        
        self.counter_label = ttk.Label(control_frame, text="Requests: 0")
        self.counter_label.pack(side=tk.RIGHT)
        
        # Main content frame
        content_frame = ttk.Frame(main_frame)
        content_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(0, weight=1)
        
        # Paned window for resizable sections
        paned_window = ttk.PanedWindow(content_frame, orient=tk.VERTICAL)
        paned_window.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Request list frame
        list_frame = ttk.LabelFrame(paned_window, text="Captured Requests", padding="5")
        paned_window.add(list_frame, weight=1)
        
        # Treeview for requests
        columns = ("Time", "Method", "Host", "Path", "Status", "Size")
        self.request_tree = ttk.Treeview(list_frame, columns=columns, show="tree headings", height=12)
        
        # Configure columns
        self.request_tree.heading("#0", text="ID")
        self.request_tree.column("#0", width=50, minwidth=50)
        
        column_widths = {"Time": 80, "Method": 70, "Host": 200, "Path": 300, "Status": 60, "Size": 80}
        for col in columns:
            self.request_tree.heading(col, text=col)
            self.request_tree.column(col, width=column_widths.get(col, 100), minwidth=50)
        
        # Scrollbars for treeview
        tree_scrollbar_v = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.request_tree.yview)
        tree_scrollbar_h = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.request_tree.xview)
        
        self.request_tree.configure(yscrollcommand=tree_scrollbar_v.set, xscrollcommand=tree_scrollbar_h.set)
        
        self.request_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scrollbar_v.grid(row=0, column=1, sticky=(tk.N, tk.S))
        tree_scrollbar_h.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Bind selection event
        self.request_tree.bind("<<TreeviewSelect>>", self.on_request_select)
        
        # Details frame
        details_frame = ttk.LabelFrame(paned_window, text="Request Details", padding="5")
        paned_window.add(details_frame, weight=1)
        
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)
        
        # Notebook for tabs
        self.details_notebook = ttk.Notebook(details_frame)
        self.details_notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # URL tab
        url_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(url_frame, text="URL")
        self.url_text = scrolledtext.ScrolledText(url_frame, height=4, wrap=tk.WORD, font=("Consolas", 10))
        self.url_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Headers tab
        headers_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(headers_frame, text="Request Headers")
        self.headers_text = scrolledtext.ScrolledText(headers_frame, height=10, wrap=tk.NONE, font=("Consolas", 9))
        self.headers_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Body tab
        body_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(body_frame, text="Request Body")
        self.body_text = scrolledtext.ScrolledText(body_frame, height=10, wrap=tk.WORD, font=("Consolas", 9))
        self.body_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Response headers tab
        resp_headers_frame = ttk.Frame(self.details_notebook)
        self.details_notebook.add(resp_headers_frame, text="Response Headers")
        self.resp_headers_text = scrolledtext.ScrolledText(resp_headers_frame, height=10, wrap=tk.NONE, font=("Consolas", 9))
        self.resp_headers_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Store requests data
        self.requests_data = {}
        self.responses_data = {}
        self.request_counter = 0
        
        # Monitoring thread
        self.monitoring = False
        self.monitor_thread = None
        
        # Check for/if log file exists on startup
        self.check_log_file_status()
    
    def check_log_file_status(self):
        """Check if log file exists and show status"""
        if os.path.exists(self.log_file):
            self.status_label.config(text="Status: Log file found", foreground="orange")
        else:
            self.status_label.config(text="Status: Waiting for mitmproxy", foreground="red")
    
    def start_monitoring(self):
        """Start monitoring the log file"""
        if not os.path.exists(self.log_file):
            messagebox.showwarning("Log File Not Found", 
                                 f"Log file '{self.log_file}' not found.\n\n"
                                 "Please start mitmproxy first:\n"
                                 "mitmproxy -s capture.py")
            return
        
        self.monitoring = True
        self.monitor_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Monitoring Active", foreground="green")
        
        # Reset file position to read from beginning
        self.last_position = 0
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_log_file, daemon=True)
        self.monitor_thread.start()
        
        # Start checking queue
        self.check_queue()
    
    def stop_monitoring(self):
        """Stop monitoring the log file"""
        self.monitoring = False
        self.monitor_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Monitoring Stopped", foreground="red")
    
    def monitor_log_file(self):
        """Monitor the log file for new entries"""
        while self.monitoring:
            try:
                if os.path.exists(self.log_file):
                    with open(self.log_file, "r", encoding="utf-8") as f:
                        f.seek(self.last_position)
                        lines = f.readlines()
                        self.last_position = f.tell()
                        
                        for line in lines:
                            line = line.strip()
                            if line:
                                try:
                                    data = json.loads(line)
                                    if "type" in data and data["type"] == "response":
                                        self.request_queue.put(("response", data))
                                    else:
                                        self.request_queue.put(("request", data))
                                except json.JSONDecodeError as e:
                                    print(f"JSON decode error: {e}")
                                    continue
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(1)
    
    def check_queue(self):
        """Check for new requests in the queue"""
        if not self.monitoring:
            return
        
        try:
            while True:
                item = self.request_queue.get_nowait()
                if item[0] == "request":
                    self.add_request(item[1])
                elif item[0] == "response":
                    self.update_response(item[1])
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.check_queue)
    
    def add_request(self, request_data):
        """Add a new request to the UI"""
        self.request_counter += 1
        req_id = str(self.request_counter)
        
        # Store full data
        self.requests_data[req_id] = request_data
        
        # Format size
        size = request_data.get("content_length", 0)
        size_str = f"{size}B" if size < 1024 else f"{size//1024}KB"
        
        # Add to treeview
        self.request_tree.insert("", tk.END, 
                                iid=req_id,
                                text=req_id,
                                values=(
                                    request_data["time"],
                                    request_data["method"],
                                    request_data.get("host", ""),
                                    request_data.get("path", "")[:50] + "..." if len(request_data.get("path", "")) > 50 else request_data.get("path", ""),
                                    "Pending",
                                    size_str
                                ))
        
        # Auto-scroll to latest
        self.request_tree.see(req_id)
        
        # Update counter
        self.counter_label.config(text=f"Requests: {self.request_counter}")
    
    def update_response(self, response_data):
        """Update request with response data"""
        # Find the request by ID
        req_id_to_update = None
        for req_id, req_data in self.requests_data.items():
            if req_data.get("id") == response_data.get("id"):
                req_id_to_update = req_id
                break
        
        if req_id_to_update:
            # Store response data
            self.responses_data[req_id_to_update] = response_data
            
            # Update the treeview item
            current_values = list(self.request_tree.item(req_id_to_update)["values"])
            current_values[4] = str(response_data.get("status_code", "Unknown"))  # Status column
            self.request_tree.item(req_id_to_update, values=current_values)
    
    def on_request_select(self, event):
        """Handle request selection"""
        selection = self.request_tree.selection()
        if not selection:
            return
        
        req_id = selection[0]
        if req_id not in self.requests_data:
            return
        
        request_data = self.requests_data[req_id]
        response_data = self.responses_data.get(req_id, {})
        
        # Update URL tab
        self.url_text.delete(1.0, tk.END)
        self.url_text.insert(1.0, request_data.get("url", ""))
        
        # Update headers tab
        self.headers_text.delete(1.0, tk.END)
        headers = request_data.get("headers", {})
        headers_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
        self.headers_text.insert(1.0, headers_str)
        
        # Update body tab
        self.body_text.delete(1.0, tk.END)
        body = request_data.get("body", "")
        self.body_text.insert(1.0, body)
        
        # Update response headers tab
        self.resp_headers_text.delete(1.0, tk.END)
        resp_headers = response_data.get("response_headers", {})
        if resp_headers:
            resp_headers_str = "\n".join([f"{k}: {v}" for k, v in resp_headers.items()])
            self.resp_headers_text.insert(1.0, resp_headers_str)
        else:
            self.resp_headers_text.insert(1.0, "No response data available")
    
    def clear_log(self):
        """Clear all logged requests"""
        for item in self.request_tree.get_children():
            self.request_tree.delete(item)
        
        self.requests_data.clear()
        self.responses_data.clear()
        self.request_counter = 0
        
        # Clear details
        self.url_text.delete(1.0, tk.END)
        self.headers_text.delete(1.0, tk.END)
        self.body_text.delete(1.0, tk.END)
        self.resp_headers_text.delete(1.0, tk.END)
        
        # Update counter
        self.counter_label.config(text="Requests: 0")
        
        # Reset file position
        self.last_position = 0
    
    def refresh_requests(self):
        """Refresh and reload all requests from log file"""
        if not os.path.exists(self.log_file):
            messagebox.showinfo("No Log File", "No log file found to refresh from.")
            return
        
        # Clear current data
        self.clear_log()
        
        # Read entire log file
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                
                for line in lines:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if "type" in data and data["type"] == "response":
                                self.update_response(data)
                            else:
                                self.add_request(data)
                        except json.JSONDecodeError:
                            continue
                
                # Update file position
                self.last_position = f.tell()
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh requests: {str(e)}")


def main():
    root = tk.Tk()
    app = MITMProxyUI(root)
    
    def on_closing():
        app.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        on_closing()


if __name__ == "__main__":
    main()
