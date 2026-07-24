# METATRON Enterprise Suite Features

## Summary
Extended METATRON with enterprise-grade capabilities including audit logging, scheduled scans, and a comprehensive dashboard for security operations management.

---

## 1. Audit Logging System

### Backend (`main.py`)
- **Function**: `audit_event(actor, event_type, details, scan_id, vuln_id, schedule_id)`
- **Database**: `audit_logs` table with columns:
  - `id`: Primary key
  - `event_time`: Timestamp of event
  - `actor`: User or system performing action
  - `event_type`: Type of event (scan_started, vulnerability_exploit, terminal_command, etc.)
  - `details`: Event description
  - `scan_id`, `vuln_id`, `schedule_id`: Foreign keys for correlation

### Logged Events
- **Scan Operations**: scan_started, scan_paused
- **Vulnerability Actions**: vulnerability_exploit
- **Terminal Activity**: terminal_command, sensitive_search
- **History Management**: history_deleted
- **Schedule Events**: schedule_created, schedule_deleted, schedule_executed, schedule_triggered

### API Endpoint
- **GET /audit** - Retrieve audit logs (max 200 entries, sorted by most recent)
  ```json
  Response:
  [
    {
      "id": 1,
      "event_time": "2024-01-15 14:30:00",
      "actor": "web",
      "event_type": "scan_started",
      "details": "Scan started for 192.168.1.1",
      "scan_id": "abc12345",
      "vuln_id": null,
      "schedule_id": null
    }
  ]
  ```

---

## 2. Scheduled Scans System

### Backend (`db.py`)
- **Database**: `scheduled_scans` table with columns:
  - `id`: Primary key
  - `target`: IP or domain to scan
  - `scan_type`: quick, standard, deep, custom
  - `intensity`: low, medium, high
  - `options`: JSON configuration
  - `schedule_at`: ISO format datetime
  - `enabled`: Boolean to activate/deactivate
  - `created_at`: When schedule was created
  - `last_run_at`: When it last executed
  - `status`: scheduled, running, triggered

### Schedule Monitor
- **Background Thread**: `schedule_monitor()` runs continuously on app startup
- **Behavior**: Checks every 30 seconds for schedules due for execution
- **Automation**: Automatically creates and starts scan when schedule_at time is reached
- **Integration**: Logs schedule_triggered audit event when auto-executing

### API Endpoints

#### GET /schedule
Retrieve all scheduled scans
```json
Response:
[
  {
    "id": 1,
    "target": "192.168.1.1",
    "scan_type": "standard",
    "intensity": "medium",
    "options": {},
    "schedule_at": "2024-01-20 22:00:00",
    "enabled": true,
    "created_at": "2024-01-15 10:00:00",
    "last_run_at": null,
    "status": "scheduled"
  }
]
```

#### POST /schedule
Create a new scheduled scan
```json
Request Body:
{
  "target": "192.168.1.1",
  "scan_type": "standard",
  "intensity": "medium",
  "options": {},
  "schedule_at": "2024-01-20T22:00:00Z",
  "enabled": true
}

Response:
{
  "schedule_id": 1,
  "message": "Schedule created"
}
```

#### POST /schedule/{schedule_id}/run
Execute a scheduled scan immediately
```json
Response:
{
  "scan_id": "xyz789",
  "schedule_id": 1,
  "message": "Scheduled scan started"
}
```

#### DELETE /schedule/{schedule_id}
Remove a scheduled scan

---

## 3. Frontend Enterprise UI

### Schedule Management (Settings → Programación de Escaneos)
- **Target**: Input field for IP or domain
- **Scan Type**: Dropdown (quick/standard/deep/custom)
- **Intensity**: Dropdown (low/medium/high)
- **Schedule At**: DateTime picker for when to execute
- **Enabled Toggle**: Activate/deactivate without deleting
- **Actions**: Create schedule and view all programmed scans

### Scheduled Scans View
- **List Display**: All scheduled scans with status badges
- **Quick Actions**:
  - Run Now: Execute schedule immediately
  - Delete: Remove schedule from database
- **Status Indicators**: Scheduled, Running, Executed

### Audit Log View
- **Event Timeline**: Chronological display of all system events
- **Event Details**:
  - Event type and timestamp
  - Actor (web, system, api)
  - Event description
- **Filtering**: Last 200 events displayed
- **Auto-refresh**: Updates every 30 seconds

---

## 4. Frontend Functions

### Loading Functions
```javascript
loadScheduledScans()      // Fetch and render all scheduled scans
loadAuditLogs()          // Fetch and render audit events
```

### Schedule Management Functions
```javascript
createSchedule(event)              // Create new schedule from form
runScheduleNow(scheduleId)        // Execute schedule immediately
deleteScheduledScan(scheduleId)   // Delete schedule entry
```

### Rendering Functions
```javascript
renderScheduledScansList(schedules)  // Render schedule cards with actions
renderAuditLogList(logs)             // Render audit event timeline
formatScheduleStatus(status)         // Format schedule status display
```

---

## 5. Integration Points

### Data Correlation
- All scan operations link to `scan_id` in audit logs
- Vulnerabilities link to `vuln_id` for exploit tracking
- Scheduled scans link to `schedule_id` for execution history

### Real-time Updates
- Dashboard refreshes audit logs and schedules every 30 seconds
- Schedule monitor checks for due scans every 30 seconds
- Startup thread runs `schedule_monitor()` in background

### Security Events Tracked
- Who initiated each action (actor field)
- What action was performed (event_type)
- When it happened (event_time)
- Context of the action (scan_id, vuln_id, schedule_id)
- Detailed description of the event

---

## 6. Enterprise Dashboard

The settings panel now includes:

1. **General Configuration**: API key and notification settings
2. **Scheduled Scans**: Create and manage recurring security scans
3. **Scheduled Scans List**: View all scheduled scans with status
4. **Audit Log**: Complete event history for compliance and security monitoring

---

## 7. Database Schema Extensions

### audit_logs Table
```sql
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT,
    actor TEXT,
    event_type TEXT,
    details TEXT,
    scan_id TEXT,
    vuln_id INTEGER,
    schedule_id INTEGER
)
```

### scheduled_scans Table
```sql
CREATE TABLE scheduled_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_type TEXT,
    intensity TEXT,
    options TEXT,
    schedule_at TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT,
    last_run_at TEXT,
    status TEXT DEFAULT 'scheduled'
)
```

---

## 8. Compliance & Operations

- **Audit Trail**: Complete record of all security operations
- **Compliance Ready**: Event logging for security audits
- **Automated Scans**: Schedule recurring security assessments
- **Event Correlation**: Link events across scans and vulnerabilities
- **Historical Data**: Retention of all events for forensic analysis

---

## Future Enhancements

1. **Advanced Filtering**: Filter audit logs by date range, actor, event type
2. **Export Functionality**: Export audit logs to CSV/JSON for reporting
3. **Alerting**: Notify on failed scans or critical vulnerabilities
4. **Retention Policies**: Configure audit log retention periods
5. **Role-Based Access**: Different audit log visibility by user role
6. **Email Notifications**: Schedule scan completion alerts
7. **Integration**: Webhook support for SIEM integration

---

**Version**: 1.0 Enterprise
**Last Updated**: January 2024
