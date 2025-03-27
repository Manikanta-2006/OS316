import tkinter as tk
from tkinter import ttk
import win32evtlog
import win32evtlogutil
import win32security
import time
import threading

MAX_LOGS = 500  # Maximum logs to retain

class SecurityLogViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Security Log Viewer")
        self.root.geometry("1000x500")

        self.refresh_rate = 5000  # Default refresh rate (ms)
        self.create_widgets()
        self.running = True
        self.start_logging()

    def create_widgets(self):
        columns = ("Time", "Event ID", "User", "Message")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=250)

        self.tree.pack(fill=tk.BOTH, expand=True)


        # Control frame
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, pady=5)

        tk.Label(control_frame, text="Refresh Timer (ms):").pack(side=tk.LEFT, padx=5)
        self.refresh_timer = tk.Spinbox(control_frame, from_=1000, to=10000, increment=1000, command=self.update_refresh_rate)
        self.refresh_timer.pack(side=tk.LEFT)
        self.refresh_timer.insert(0, str(self.refresh_rate))

        self.clear_button = tk.Button(control_frame, text="Clear", command=self.clear_table)
        self.clear_button.pack(side=tk.RIGHT, padx=5)

    def update_refresh_rate(self):
        try:
            self.refresh_rate = int(self.refresh_timer.get())
        except ValueError:
            self.refresh_rate = 5000  # Default fallback

    def clear_table(self):
        """Removes all entries from the table."""
        for row in self.tree.get_children():
            self.tree.delete(row)

    def get_security_logs(self):
        """Fetches the latest security logs from Windows Event Viewer."""
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            logs = []

            if events:
                for event in events[:10]:  # Fetch last 10 logs
                    time_generated = event.TimeGenerated
                    formatted_time = f"{time_generated.hour:02}:{time_generated.minute:02}:{time_generated.second:02}"
                    
                    event_id = event.EventID
                    try:
                        user = win32security.LookupAccountSid(None, event.Sid)[0]
                    except:
                        user = "SYSTEM"
                    message = win32evtlogutil.SafeFormatMessage(event, "Security")

                    logs.append((formatted_time, event_id, user, message[:100]))  # Limit message length

            win32evtlog.CloseEventLog(hand)
            return logs

        except Exception as e:
            return [("Error", "N/A", "N/A", str(e))]

    def log_security_events(self):
        """Continuously updates the security logs."""
        while self.running:
            logs = self.get_security_logs()

            for log in reversed(logs):  # Insert new logs at the top
                self.tree.insert("", 0, values=log)

            # Keep only the latest MAX_LOGS entries
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
