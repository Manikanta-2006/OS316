# Real-Time Security Event Logger

## 📌 Project Overview
The **Real-Time Security Event Logger** is a Windows-based security monitoring tool that continuously fetches and displays system security logs. It categorizes event logs based on predefined threat levels and provides real-time visualization for enhanced security awareness.

## 🚀 Features and Functionality
-  **Real-Time Event Logging**: Fetches Windows Security logs dynamically.
-  **Threat Level Categorization**: Assigns threat levels using color-coded indicators.
-  **User Identification**: Extracts and displays event-triggering users.
-  **Event Filtering**: Filters critical events such as failed logins and privilege escalations.
-  **Graphical User Interface (GUI)**: Interactive and user-friendly interface using Tkinter.
-  **Automated Updates**: Continuously updates logs without manual refresh.
-  **Process & Account Monitoring**: Detects new processes, account creations, and deletions.
-  **Threat Simulation Support**: Allows testing of security responses with simulated threats.

## 🔧 Technologies Used
- **Programming Language**: Python
- **Libraries**:
  - `tkinter` - GUI Development
  - `win32evtlog` - Windows Event Log Access
  - `win32evtlogutil` - Event Formatting
  - `win32security` - User & Security Information
  - `threading` - Background Processing
  - `time` - Log Refresh Timing

## 🔍 Threat Level Indicators
Each security event is categorized based on severity, represented with color-coded indicators:

- 🔴 **High (Red)**: Unauthorized access attempts, account deletions, credential failures.
- 🟠 **Medium (Orange)**: Privilege escalations, new process creations.
- 🟡 **Low (Yellow)**: User logoff events.
- 🔵 **Informational (Blue)**: Process execution logs.
- 🟣 **Service-Level (Purple)**: Service installation activities.
- 🟢 **Account Management (Green)**: User account creation.

## 🔑 Security Events Tracked
The logger monitors key security events using **Event IDs**:

- **4625** - Unauthorized Login Attempt 🔴
- **4634** - User Logoff 🟡
- **4672** - Admin Privilege Granted 🟠
- **4688** - New Process Created 🔵
- **4697** - Service Installed 🟣
- **4720** - User Account Created 🟢
- **4726** - User Account Deleted 🔴
- **5379** - Credential Validation Failure 🔴

## 📥 Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/YourUsername/Security-Event-Logger.git
