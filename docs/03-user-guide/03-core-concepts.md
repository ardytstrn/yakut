# Core Concepts in Yakut

To effectively use Yakut, it's essential to understand its fundamental building blocks
and how they interact. This section explains the core concepts you'll encounter
frequently.

## 1. Workspaces

- **Definition:** A workspace is an isolated environment within Yakut used to organize data for a specific engagement, project or target set. All data related to an engagement —such as discovered hosts, services, vulnerabilities, collected loot, notes and command history— is typically scoped to the active workspace.
- **Purpose:**
  - **Organization:** Keeps data from different penetration tests or research projects separate and manageable
  - **Collaboration**
  - **Reporting:** Makes it easier to generate reports specific to an engagement
- **Key Operations:** Creating, listing, switching, deleting and archiving

## 2. Targets

- **Definition:** A target represents any entity you are assessing or engaging with. This is most commonly a host (IP address or hostname) but could conceptually be extended to web applications, APIs, cloud resources or even organizations/individiuals for OSINT purposes.
- **Attributes:** Yakut aims to store rich information about targets, including:
  - IP addresses, hostnames, MAC addresses
  - Operating system details
  - Open ports and running services (with versions)
  - Discovered vulnerabilities (linked from capabilities or manual entry)
  - Associated loot and credentials
  - User notes and tags
- **Purpose:** Centralizes all information about your targets, making it easy to query, correlate data and select targets for capability execution.
- **Key Operations:** Adding, listing, viewing details, updating, deleting, tagging and managing services/vulnerabilities associated with targets.

## 3. Capabilities

- **Definition:** Capabilities are the active, functional heart of Yakut. They are self-contained units of Ruby code designed to perform specific, well-defined tasks across the entire offensive security lifecycle.
- **Purpose:** To provide reusable components for scanning, exploitation, post-exploitation, payload delivery, etc.
- **Types:** `Exploit`, `Intel`, `Recon`, `Delivery`, `Post`, `Payload`, `Encoder`, `Cloud`, `AISec` (experimental)

## 4. Options

- **Definition:** Options are configurable parameters that control the behavior of Yakut.
- **Scope:**
  - Global
  - Capability
  - Payload
- **Types:** Options can be various types, such as strings, integers, booleans, IP addresses, file paths, enumerated lists (enums). Yakut provides validation for these.
- **Required vs. Optional:** Some options are mandatory for a capability to run, while others are optional or have default values. The `capability options` command will indicate this.

## 5. Jobs

- **Definition:** A job represents a capability or task that is running in the background.
- **Purpose:** Improves interactivity and allows for multitasking within the framework.

## 6. Sessions

- **Definition:** A session represents an active, interactive connection established with a compromised target system after a successful exploit and payload execution.
- **Purpose:** Provides a means to interact with the target, gather information, escalate privileges, pivot to other systems and deploy further post-exploitation capabilities.

## 7. Loots

- **Definition:** Loot refers to any valuable information or data collected from target systems during an engagement.
- **Types:** Credentials, password hashes, sensitive files, screenshots, configuration details, PII, keys, etc.
- **Purpose:** Centralizes the storage and management of all collected data, making it easy to search, reference and use in reporting. Loot is typically associated with a specific host and service within a workspace.

## 8. Contexts

- **Definition:** As mentioned in the [CLI Overview](./01-cli-overview.md#2-the-command-prompt), Yakut's console operates in different contexts. The available commands and the effect of commands like `set` or `run` depend on the current context (Global, Workspace, Capability, Session).
- **Switching Contexts:**
  - `workspace use <name>`: Switches to workspace context.
  - `capability use <cap_name>`: Switches to capability context.
  - `sessions interact <id>`: Switches to session context.
  - `back`: Moves out of the current context (e.g., from capability to workspace/global).

## 9. Scope Definition

- **Definition:** Within each workspace, users can formally define the authorized scope of the engagement. This includes IP ranges, domains, specific applications or even excluded targets.
- **Purpose:** Yakut can use this scope definition to provide warnings or even (optionally) block actions that appear to target systems outside the defined scope.
- **Interaction:**
  - `scope define --include 192.168.1.0/24 --exclude 192.168.1.100 --notes "Internal pentest for HR department"`
  - `scope show`
  - When a capability is about to run against a target, Yakut would check if the target is within scope.

---

Understanding these core concepts will significantly enhance your ability to navigate and utilize the Yakut framework. The next section, **[Common Commands](./04-common-commands.md)**, will show you how to put these concepts into action.
