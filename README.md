# PhishPhalanx – Threat Intelligence & Phishing Incident Repository

## Overview

PhishPhalanx is an enterprise-grade threat intelligence and phishing incident management system. The CLI application enables security analysts to:

- **Report phishing incidents** with severity classification (low/medium/high)
- **Manage a domain blacklist** with SHA-256 hashing and MITRE ATT&CK defanging conventions
- **Query open incidents** filtered by danger level
- **Track incident status** through workflow states (open → investigating → closed)
- **Remove false positives** with confirmation dialogs
- **Perform real-time blacklist lookups** for domain validation

All data persists in a cloud-based MongoDB Atlas cluster, enabling multi-team collaboration and historical analysis of phishing campaigns.

---

## Cloud Database

**MongoDB Atlas** was chosen for the following reasons:

- **Flexible Schema**: Documents store nested incident metadata without rigid table definitions
- **Scalability**: Horizontal scaling across multiple nodes as threat intelligence grows
- **Global Distribution**: MongoDB Atlas clusters can be deployed across regions for low-latency access
- **Security**: Built-in authentication, encryption at rest, and network access controls
- **Indexing**: Fast lookups on domainHash (SHA-256) and incidentId fields using indexed queries
- **TTL Collections** (future): Automatic expiration of old incidents for compliance/retention policies

**Collections:**
- `incidents` – Phishing incident reports with severity and status tracking
- `blacklists` – Malicious domains with SHA-256 hashes and defanged URLs

---

## Development Environment

**Runtime & Language:**
- **Node.js** (v16+) – JavaScript runtime environment
- **ECMAScript 6 (ES2022)** – Modern JavaScript with async/await

**Core Dependencies:**
- **Mongoose** (v8.15.0) – MongoDB ODM with schema validation
- **dotenv** (v16.6.1) – Environment variable management for sensitive credentials
- **readline** (built-in) – Terminal-based interactive prompts

**Development Tools:**
- **npm** – Package manager and task runner
- **eslint** (.eslintrc.json) – Code quality and style enforcement

**Architecture:**
- **MVC Pattern** – Separation of models (schemas), business logic (incidents.js, blacklist.js), and UI (index.js)
- **Async/Await** – Non-blocking I/O for database operations
- **Try/Catch Error Handling** – Graceful error recovery throughout

---

## Relational Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    MongoDB Atlas (Cloud)                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────────────────────┐   ┌──────────────────────────┐ │
│  │   incidents Collection     │   │  blacklists Collection   │ │
│  ├────────────────────────────┤   ├──────────────────────────┤ │
│  │ _id (ObjectId)             │   │ _id (ObjectId)           │ │
│  │ incidentId (String)        │   │ domainHash (String)      │ │
│  │   [Unique, Indexed]        │   │   [Unique, Indexed]      │ │
│  │                            │   │                          │ │
│  │ targetDomain (String)      │   │ originalDomain (String)  │ │
│  │   [Required]               │   │   [Defanged Format]      │ │
│  │   [e.g. evil[.]com]        │   │   [e.g. hxxp://...]      │ │
│  │                            │   │                          │ │
│  │ dangerLevel (Enum)         │   │ addedAt (Date)           │ │
│  │   [low | medium | high]    │   │   [Timestamp]            │ │
│  │                            │   │                          │ │
│  │ status (Enum)              │   │ ──────────────────────── │ │
│  │   [open | investigating    │   │                          │ │
│  │    | closed]               │   │ Example Document:        │ │
│  │                            │   │ {                        │ │
│  │ reporterEmail (String)     │   │   _id: ObjectId(...),    │ │
│  │   [Optional]               │   │   domainHash: "abc123...",
│  │                            │   │   originalDomain:        │ │
│  │ timestamp (Date)           │   │     "hxxp://evil[.]com", │ │
│  │   [Created Date]           │   │   addedAt: 2026-05-27... │ │
│  │                            │   │ }                        │ │
│  │ ──────────────────────────│   │                          │ │
│  │ Example Document:         │   └──────────────────────────┘ │
│  │ {                         │                                 │
│  │   _id: ObjectId(...),     │   SHA-256 Hashing:              │
│  │   incidentId: "INC-1001", │   Input:  "evil.com"            │
│  │   targetDomain: "hxxp://...", │  Output: 64-char hex        │
│  │   dangerLevel: "high",    │   Lookup: O(1) indexed search   │
│  │   status: "open",         │                                 │
│  │   reporterEmail: "...@...",│  Defanging Convention:          │
│  │   timestamp: 2026-05-27...│  http → hxxp                    │
│  │ }                         │  . → [.]                        │
│  │                           │                                 │
│  └────────────────────────────┘                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

                    Node.js CLI Application
                    (index.js)
                         ↓
                   ┌──────────────┐
                   │ Readline Menu│
                   └──────┬───────┘
                          │
        ┌─────────────────┼─────────────────┐
        ↓                 ↓                 ↓
   incidents.js     blacklist.js          db.js
   (CRUD Ops)       (Hash & Check)    (MongoDB Connection)
        ↓                 ↓                 ↓
   [incidents]       [blacklists]      [Atlas Cluster]
   Collection        Collection
```

---

## Video Walkthrough
(https://www.loom.com/share/de14306bd973422e8a828d2e7ddcae98)

---

## Installation & Setup

### Prerequisites
- Node.js v16 or higher
- npm (included with Node.js)
- MongoDB Atlas account and connection string

### Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/gideonagbavor8/PhishPhalanx.git
   cd PhishPhalanx
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Create `.env` file with MongoDB URI:**
   ```bash
   echo "MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/phishphalanx" > .env
   ```

4. **Seed sample data (optional):**
   ```bash
   npm run seed
   ```

5. **Start the interactive menu:**
   ```bash
   npm start
   ```

---

## Usage

### Main Menu Options

```
╔══════════════════════════════════════════════════════════╗
║          PhishPhalanx — Threat Intelligence             ║
╠══════════════════════════════════════════════════════════╣
║  1. Report a new phishing incident                      ║
║  2. Look up a domain in the blacklist                   ║
║  3. View open incidents by severity                     ║
║  4. Update an incident status                           ║
║  5. Delete a false positive incident                    ║
║  6. Exit                                                ║
╚══════════════════════════════════════════════════════════╝
```

### Example Workflows

**Report a High-Severity Incident:**
```
Choice: 1
Domain: malicious-paypal.com
Severity: high
Email: analyst@company.com
→ Creates INC-XXXXX in MongoDB
```

**Check if Domain is Blacklisted:**
```
Choice: 2
Domain: hxxps://evil[.]com/login
→ ✅ Found in blacklist or ✅ Clean
```

**View All High-Severity Open Incidents:**
```
Choice: 3
Level: high
→ Lists all incidents with dangerLevel=high and status=open
```

---

## Project Structure

```
PhishPhalanx/
├── index.js                 # Interactive CLI menu
├── package.json             # Dependencies and scripts
├── .env                     # Environment variables (git-ignored)
├── .eslintrc.json           # Code quality rules
├── README.md                # This file
├── SECURITY.md              # Security policy
│
└── src/
    ├── db.js                # MongoDB connection management
    ├── seed.js              # Database seeding script
    ├── incidents.js         # Incident CRUD operations
    ├── blacklist.js         # Domain blacklist operations
    │
    └── models/
        ├── Incident.js      # Incident schema
        └── Blacklist.js     # Blacklist schema
```

---

## API Functions

### incidents.js
- `createIncident(data)` – Create new incident
- `getIncident(incidentId)` – Fetch single incident
- `listIncidents(filters)` – Query incidents with optional filters
- `updateIncidentStatus(incidentId, newStatus)` – Update workflow status
- `deleteIncident(incidentId)` – Remove incident
- `getIncidentsBySeverity(level)` – Query open incidents by severity

### blacklist.js
- `checkBlacklist(domain)` – Check if domain is blacklisted
- `addToBlacklist(domain)` – Add domain with SHA-256 hash
- `removeBlacklistEntry(domain)` – Remove from blacklist
- `normalizeDomain(rawDomain)` – Canonicalize domain format
- `defangHostname(input)` – Apply MITRE ATT&CK defanging
- `hashDomain(value)` – Generate SHA-256 hash

### db.js
- `connectDB()` – Establish MongoDB Atlas connection
- `closeDB()` – Gracefully close connection

---

## Error Handling

All functions implement comprehensive error handling:

```javascript
try {
  // Database operation
  const result = await operation();
  console.log('✅ Success:', result);
} catch (error) {
  console.error('❌ Error:', error.message);
  throw error;
}
```

**Console Feedback:**
- ✅ Success messages with operation details
- ⚠️ Warnings for edge cases (not found, invalid input)
- ❌ Error messages with context
- ℹ️ Informational messages

---

## Useful Websites
- [MongoDB Atlas Docs](https://www.mongodb.com/docs/atlas/)
- [Mongoose Docs](https://mongoosejs.com/docs/)
- [Node.js Docs](https://nodejs.org/en/docs)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Node.js Readline Module](https://nodejs.org/api/readline.html)
- [SHA-256 Hashing](https://en.wikipedia.org/wiki/SHA-2)

---

## Future Work
- [ ] Add user authentication and role-based access control (RBAC)
- [ ] Build a web dashboard for incident visualization (React/Vue)
- [ ] Integrate live threat intelligence API feeds (VirusTotal, AlienVault)
- [ ] Implement incident escalation workflows
- [ ] Add bulk import/export for CSV incident logs
- [ ] Email notifications for high-severity incidents
- [ ] Historical analytics and trending reports
- [ ] Integration with SIEM systems (Splunk, ELK Stack)
- [ ] Mobile app for on-the-go incident reporting
- [ ] Machine learning classifier for auto-severity detection

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/awesome-feature`)
3. Commit changes with descriptive messages
4. Push to the branch (`git push origin feature/awesome-feature`)
5. Open a Pull Request

---

## License

MIT License 

---

## Support
For issues, questions, or suggestions:
- Open an issue on GitHub
- Contact: gideonagbavor8@gmail.com
- Security concerns: See [SECURITY.md](SECURITY.md)

---

**PhishPhalanx — Defending Against Phishing, One Incident at a Time** 🛡️
