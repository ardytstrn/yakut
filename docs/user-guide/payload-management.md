# Payload Management in Yakut

Payloads are a crucial component of offensive security operations. They represent the
code that executes on a target system after an `Exploit` **Capability** is successful or
when delivered via a `Delivery` **Capability**. Yakut provides a flexible system for
selecting, configuring and generating various types of payloads, with a special focus
on its advanced native agent, the YakutAgent.

This guide will cover how to manage and utilie payloads within Yakut.

- [Payload Management in Yakut](#payload-management-in-yakut)
- [1. What is a Payload in Yakut?](#1-what-is-a-payload-in-yakut)
- [2. Types of Payloads](#2-types-of-payloads)
- [3. Generating Standalone Payloads](#3-generating-standalone-payloads)
- [4. Payloads and C2 Infrastructure](#4-payloads-and-c2-infrastructure)
- [5. Payload Encoding and Evasion](#5-payload-encoding-and-evasion)

# 1. What is a Payload in Yakut?

In Yakut, a payload is the actual code or agent that performs actions on the target
machine. Its primary purposes include:

- **Establishing Command & Control (C2):** Creating a communication channel back to the Yakut framework, allowing for interactive control over compromised system (e.g., opening a shell, running YakutAgent).
- **Executing Specific Actions:** Performing predefined tasks like adding a user, executing a single command or downloading/uploading files without necessarily establishing a full interactive session.
- **Delivering Further Stages:** In staged payloads, the initial payload is small and its job is to download and execute a larger, more feature-rich second stage (like the full YakutAgent).

Yakut's `Yakut::OperationsPlatform` (specifically its `PayloadGenerationService`) and `Yakut::C2Infrastructure` work together to manage payload generation, configuration and handling of incoming connections from these payloads.

# 2. Types of Payloads

Yakut aims to support a variety of payload types to suit different scenarios and target environments:

- **Singles (Stageless Payloads):** These payloads contain all the code necessary to achieve their objective (e.g., establish a C2 session or execute a command) in a single package.
- **Stagers & Stages (Staged Payloads):**
  - **Stagers:** Small initial payloads whose sole purpose is to establish a connection back to Yakut and download the larger stage.
  - **Stages:** The actual functional payload (e.g., the full YakutAgent, a command shell) that is sent over the established connection.
- **Command Execution Payloads:** Payloads designed to execute a single command or a short script on the target system and then exit. They may or may not return output.
- **The YakutAgent (Advanced Native Agent):**
  - This is Yakut's flagship payload, envisioned as a sophisticated, multi-functional agent written primarily in Ruby.
  - **Features:**
    - In-memory execution where possible.
    - Encrypted and flexible C2 communication via channels defined by `C2` Capabilities (HTTP/S, DNS, SMB, etc.).
    - Malleable C2 profiles for enhanced evasion.
    - Extensible command set via its own internal mini-modules or scripts pushed from Yakut.
    - Capabilities for advanced post-exploitation: file system interaction, process manipulation, port forwarding, pivoting, screenshoting, keylogging, in-memory Ruby script execution, etc.
    - Designed for stability and stealth.
- **Reflective DLL / SO Injection Payloads:** Designed to be reflectively loaded into a compromised process's memory without dropping a file to disk, enhancing stealth. YakutAgent would heavily utilize this.

# 3. Generating Standalone Payloads

Sometimes you may need to generate a payload as a standalone file (e.g., an `.exe`,
`.elf`, `.py` script, or raw shellcode) to be delivered manually or via a third-party
tool. Yakut will provide a utility for this, named `yakut-payload`.

Command: `yakut-payload -p <payload_refname> LHOST=<ip> LPORT=<port> [other options] -f <format> -o /path/to/outputfile`

Example:

```bash
yakut-payload -p windows/x64/yakut_agent/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o /tmp/yakut_agent.exe
[*] Generating windows/x64/yakut_agent/reverse_tcp payload (LHOST=192.168.1.100, LPORT=4444)
[*] Output format: exe
[+] Payload size: XXXXX bytes
[+] Saved as /tmp/yakut_agent.exe
```

This utility would be developed as part of the `Yakut::OperationsPlatform`'s
`PayloadGenerationService`.

# 4. Payloads and C2 Infrastructure

A key aspect of Yakut's design is the tight integration between payloads (especially YakutAgent) and the `Yakut::C2Infrastructure`.

- `C2` Capabilities: These define _how_ Yakut listens for incoming connections and _how_ agents communicate. Examples:
  - `c2/listener/http_default`: A basic HTTP listener.
  - `c2/listener/dns_exfil_beacon`: A listener that uses DNS for C2.
  - `c2/profile/malleable_office365_traffic`: A C2 profile that makes traffic look like legitimate Office365 communication.
- **Payload Configuration:** When configuring a payload, you'll often specify which C2 listener profile it should connect to. This allows you to easily switch between different C2 strategies without regenerating the core payload logic.
- **Dynamic C2:** YakutAgent will be designed to potantially switch C2 channels or adapt its communication based on directives from the framework or pre-configured profiles.

# 5. Payload Encoding and Evasion

To bypass antivirus and other detection mechanisms, payloads often need to be encoded
or obfuscated.

- `Encoder` Capabilities: These Capabilities take raw payload code and transform it to avoid signature-based detection.
- `Evasion` Capabilities: These may provide more advanced techniques, including runtime evasion, process injection methods or modifying payload delivery to bypass specific security products.
- **Integration:**
  - The `PayloadGenerationService` (and `yakut-payload` utility) will allow specifying encoders.
  - `Exploit` and `Delivery` Capabilities might have options to apply specific evasion techniques during payload staging or execution.
