import tkinter as tk
from tkinter import ttk
import win32evtlog
import win32evtlogutil
import win32security
import time
import threading

# Max logs to keep in the table
MAX_LOGS = 500

# Event ID Mapping (basic event types)
EVENT_TYPES = {
    4624: "Successful Login",
    4625: "Failed Login",
    4634: "Logoff",
    4672: "Admin Privilege Login",
    4688: "Process Creation",
    4689: "Process Termination",
    4719: "Audit Policy Change",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4725: "User Account Disabled",
    4728: "User Added to Group",
    4732: "User Added to Privileged Group",
    4740: "User Account Locked",
    4768: "Kerberos Authentication",
    4776: "NTLM Authentication",
    4798: "User Enumeration",
    5379: "Credential Theft Detected",
}

# Threat levels based on event IDs
THREAT_LEVELS = {
    "🟢 Low": [4624, 4634, 4688, 4689],
    "🟡 Medium": [4672, 4719, 4728, 4732],
    "🟠 High": [4625, 4720, 4722, 4725, 4740, 4776, 4798],
    "🔴 Critical": [5379],
}

class SecurityLogViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Security Log Viewer")
        self.root.geometry("1200x600")

        self.refresh_rate = 2000  # Faster refresh (2 seconds)
        self.create_widgets()
        self.running = True
        self.start_logging()

    def create_widgets(self):
        self.search_frame = tk.Frame(self.root)
        self.search_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(self.search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_entry = tk.Entry(self.search_frame)
        self.search_entry.pack(side=tk.LEFT, padx=5)

        self.search_button = tk.Button(self.search_frame, text="Filter", command=self.filter_logs)
        self.search_button.pack(side=tk.LEFT)

        self.clear_button = tk.Button(self.search_frame, text="Clear", command=self.clear_filter)
        self.clear_button.pack(side=tk.LEFT)

        columns = ("Time", "Event ID", "Event Type", "User", "Threat", "Message")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180 if col != "Message" else 400)

        self.tree.pack(fill=tk.BOTH, expand=True)

    def get_threat_level(self, event_id):
        for level, ids in THREAT_LEVELS.items():
            if event_id in ids:
                return level
        return "⚪ Unknown"

    def get_security_logs(self):
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            log = None

            if events:
                event = events[0]
                time_generated = event.TimeGenerated
                formatted_time = f"{time_generated.hour:02}:{time_generated.minute:02}:{time_generated.second:02}.{time_generated.microsecond // 1000:03}"
                event_id = event.EventID
                event_type = EVENT_TYPES.get(event_id, "Unknown Event")

                try:
                    user = win32security.LookupAccountSid(None, event.Sid)[0]
                except:
                    user = "SYSTEM"

                message = win32evtlogutil.SafeFormatMessage(event, "Security")[:100]
                threat_level = self.get_threat_level(event_id)

                log = (formatted_time, event_id, event_type, user, threat_level, message)

            win32evtlog.CloseEventLog(hand)
            return log

        except Exception as e:
            return ("Error", "N/A", "N/A", "N/A", "⚪ Unknown", str(e))

    def log_security_events(self):
        while self.running:
            log = self.get_security_logs()
            if log:
                self.insert_log(log)
            time.sleep(self.refresh_rate / 1000.0)

    def insert_log(self, log):
        if log:
            self.tree.insert("", 0, values=log)

        while len(self.tree.get_children()) > MAX_LOGS:
            last_item = self.tree.get_children()[-1]
            self.tree.delete(last_item)

    def filter_logs(self):
        query = self.search_entry.get().strip().lower()
        if not query:
            return

        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            if any(query in str(value).lower() for value in values):
                self.tree.see(item)
            else:
                self.tree.detach(item)

    def clear_filter(self):
        for item in self.tree.get_children():
            self.tree.reattach(item, "", "end")
        self.search_entry.delete(0, tk.END)

    def start_logging(self):
        self.log_thread = threading.Thread(target=self.log_security_events, daemon=True)
        self.log_thread.start()

    def on_close(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityLogViewer(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
