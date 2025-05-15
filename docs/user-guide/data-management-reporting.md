# Data Management & Reporting

Throughout a penetration testing engagement, Yakut, primarily through its
`Yakut::CognitionEngine`, collects and stores a significant amount of data. This includes
information about target, discovered services, vulnerabilities, credentials, sensitive
files and notes. Effective management and eventual reporting of this data are crucial
for a successful assessment.

## 1. Data Organization in Yakut

Yakut organizes data primarily within the context of workspaces. Each workspace acts as
an isolated container for:

- **Targets:** Detailed profiles of hosts, applications and other entities under assessment.
- **Services:** Services discovered on targets.
- **Vulnerabilities:** Vulnerabilities identified on targets, often linked to specific services.
- **Loot:** Credentials, files, notes and other sensitive information gathered from targets.
- **Capability Logs:** Records of which capabilities were run, against which targets and their high-level results.
- **Session Logs:** Detailed interaction logs for active C2 sessions.
- **Notes:** General notes related to the engagement or specific entities.

## 2. Managing Loot

"Loot" refers to any valuable data obtained during an engagement. Yakut provides commands
to manage this effectively.

- **Automatic Loot Collection:** Many `Exploit`, `Post` and `Intel` **Capabilities** are designed to automatically report discovered loot (e.g., credentials, sensitive files, API keys) to the `Yakut::CognitionEngine`. This data is then stored within the current workspace and linked to the relevant target or service.
- **Manual Loot Addition:** You can also add loot manually using the `loot add` command.

```console
yakut [ws:ACME_Corp_Q3_Audit] > loot add creds --host DC01_Admin_Access --service rdp --user "ACME\DomainAdmin" --secret "ComplexP@ssw0rd!" --notes "RDP creds found in admin's desktop note."
[+] Loot item (creds) added (ID: 12).
```

## 3. Notes and Tagging

- **Notes:** Yakut allows adding notes to various entities.
  - Workspaces
  - Targets
  - Loots
- **Tags:** Tagging is a powerful way to categorize and organize targets, loot and other data types.
  - Tags can be used in `list` commands for filtering.

## 4. Reporting

While detailed reporting features are part of Yakut's future roadmap, the structured data
collecte by the `Yakut::CognitionEngine` is designed to faciliate comprehensive report
generation.

- **Exportable Data:** Most data lists (targets, loots, vulns) will have export options to common formats like CSV, JSON and XML.
- **Report Sections:**
  - Executive summary
  - Scope of engagement (pulled from `workspace scope`)
  - Methodology overview
  - Findings summary (e.g., number of critical vulnerabilities, systems compromised)
  - Detailed findings (per vulnerability or per host, including descriptions, evidence, risk ratings, remediation advice)
  - Loot summary (e.g., types of credentials obtained)
  - Attack narratives / timelines (generated from `Orchestration` capability logs and session logs)
  - Appendices (e.g., full list of scanned ports, raw tool outputs)
- **Command-Line Report Generation:**

```console
yakut [ws:ACME_Corp_Q3_Audit] > report generate --format pdf --output "ACME_Q3_Pentest_Report.pdf"
```

## 5. Data Backup and Archiving

- **Workspaces:** Since each workspace's data is often contained within its directory or specific database file, backing up a workspace can be as simple as copying that directory/file.
- `yakut-db backup <workspace_name> <backup_path>`
- `workspace archive <workspace_name>`: This command will likely export the workspace data to a compressed archive and mark the workspace as inactive in the Yakut console.
