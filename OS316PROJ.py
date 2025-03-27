import tkinter as tk
from tkinter import ttk
import win32evtlog
import win32evtlogutil
import win32security
import time
import threading

MAX_LOGS = 500  # Maximum logs to retain

# 🔍 Event ID Mapping with Threat Levels
THREAT_LEVELS = {
    4625: ("Failed Login Attempt", "High"),
    4720: ("New User Created", "Medium"),
    4732: ("User Added to Admin Group", "Critical"),
    4624: ("Successful Login", "Medium"),
    1102: ("Security Log Cleared", "Critical"),
    4798: ("User Account Recon", "High"),
}

# 🎨 Emoji Indicators for Threat Levels
THREAT_ICONS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}

class SecurityLogViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Security Log Viewer")
        self.root.geometry("1100x500")

        self.refresh_rate = 2000  # Update every 2 seconds
        self.create_widgets()
        self.running = True
        self.start_logging()

    def create_widgets(self):
        # Table to display logs
        columns = ("Time", "Event ID", "Event Type", "Threat Level", "User", "Message")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Control Panel
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, pady=5)

        tk.Label(control_frame, text="Refresh Timer (ms):").pack(side=tk.LEFT, padx=5)
        self.refresh_timer = tk.Spinbox(control_frame, from_=500, to=10000, increment=500, command=self.update_refresh_rate)
        self.refresh_timer.pack(side=tk.LEFT)
        self.refresh_timer.insert(0, str(self.refresh_rate))

        self.clear_button = tk.Button(control_frame, text="Clear", command=self.clear_table)
        self.clear_button.pack(side=tk.RIGHT, padx=5)

    def update_refresh_rate(self):
        """Update the refresh rate from user input."""
        try:
            self.refresh_rate = int(self.refresh_timer.get())
        except ValueError:
            self.refresh_rate = 2000  # Default fallback

    def clear_table(self):
        """Remove all logs from the table."""
        for row in self.tree.get_children():
            self.tree.delete(row)

    def get_security_logs(self):
        """Fetch the latest security log from Windows Event Viewer."""
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)

            log = None
            if events:
                event = events[0]  # Get the latest event
                time_generated = event.TimeGenerated
                formatted_time = f"{time_generated.hour:02}:{time_generated.minute:02}:{time_generated.second:02}.{time_generated.microsecond // 1000:03}"

                event_id = event.EventID
                event_type, threat_level = THREAT_LEVELS.get(event_id, ("Unknown Event", "Low"))
                threat_icon = THREAT_ICONS.get(threat_level, "⚪")  # Default to a white circle

                try:
                    user = win32security.LookupAccountSid(None, event.Sid)[0]
                except:
                    user = "SYSTEM"

                message = win32evtlogutil.SafeFormatMessage(event, "Security")
                log = (formatted_time, event_id, event_type, f"{threat_level} {threat_icon}", user, message[:100])  # Limit message length

            win32evtlog.CloseEventLog(hand)
            return log

        except Exception as e:
            return ("Error", "N/A", "Error Fetching Logs", "N/A", "N/A", str(e))

    def log_security_events(self):
        """Continuously update the security logs in real-time."""
        while self.running:
            log = self.get_security_logs()

            if log and log[0] != "Error":  # Only add valid logs
                self.tree.insert("", 0, values=log)

                # Keep only the latest MAX_LOGS
                while len(self.tree.get_children()) > MAX_LOGS:
                    last_item = self.tree.get_children()[-1]
                    self.tree.delete(last_item)

            time.sleep(self.refresh_rate / 1000.0)

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
