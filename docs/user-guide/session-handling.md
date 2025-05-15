# Session Handling in Yakut

Once an `Exploit` Capability has successfully delivered a payload and esablished a
connection back to Yakut, you gain a _Session_. A Session represents an active,
interactive channel to the compromised target system. It allows you to perform
post-exploitation activities, gather further intelligence and potentially pivot
to other systems within the network.

Yakut's `Yakut::OperationsPlatform` (via its `SessionOrchestrationService`) and `Yakut::C2Infrastructure` are responsible for managing these sessions.

- [Session Handling in Yakut](#session-handling-in-yakut)
- [1. What is a Session?](#1-what-is-a-session)

# 1. What is a Session?

- **Interactive Control:** A session provides you with a means to execute commands, run scripts, transfer files and generally control the target machine.
- **Types of Sessions:**
  - **YakutAgent Sessions:** The most powerful and flexible type, utilizing Yakut's advanced, Ruby-based agent. These offer a rich set of built-in commands, in-memory execution capabilities, and integration with Yakut's C2 profiles and post-exploitation Capabilities.
  - **Shell Sessions:** Basic command-line shells (e.g., `cmd.exe`, `/bin/bash`, `powershell.exe`) obtained via simpler payloads. Functionality is limited to standard shell commands.
