# Working with Capabilities

Capabilities are the core functional units within Yakut. hey encapsulate a wide array of
actions, from reconnaissance and exploitation to post-exploitation and utility tasks.
This guide will detail how to effectively find, understand, configure and run
Capabilities to achieve your security assessment objectives.

## 1. What are Capabilities?

In Yakut, a capability is an evolution of the traditional "module" concept. It's a
self-contained piece of Ruby code, managed by the `Yakut::OperationsPlatform`. Each
capability is defined by:

- **A specific type:** Indicating its general purpose (e.g., `Exploit`, `Intel`, `Recon`, `C2`, `Campaign`).
- **Rich metadata:** Detailed information about its function, authors, targets, reliability, impact, and operational security (OPSEC) considerations.
- **Configurable options:** Parameters that allow you to tailor its behavior.

## 2. Capability Naming & Discovery Philosophy in Yakut

Yakut employs a sophisticated approach to capability naming and discovery.

- **Canonical Module Paths (for Organization & Developers):** Capabilities are organized on the filesystem and identified by a structured path:

  - `<type>/<platform_or_category>/<specific_target_or_service>/<short_descriptive_name>`

- **Rich Metadata & Tagging (for Powerful Discovery):** Each capability is accompanied by extensive metadata, including: `title`, `ref_name`, `type`, `tags`, `description`, `reliability_score`, `impact_score`, `opsec_rating`, `cleanup_available`, `privileged`.

## 1. Understanding Module Types in Yakut

Yakut categorizes its capabilities to reflect the various stages and tasks involved in an
offensive security engagement. This includes enhancements to traditional capability types
and introduces new, specialized categories:

- **Standard Enhanced Types:**

  - `Exploit`: Capabilities designed to take advantage of specific vulnerabilities to gain unauthorized access or execute code on a target system.
  - `Auxiliary`: Used for actions that don't involve direct exploitation for access, such as scanning, enumeration, fuzzing, sniffing, denial-of-service, or administrative tasks.
  - `Post`: For post-exploitation activities conducted on a compromised system.
  - `Payload`: Code that is delivered by an exploit and runs on the target system. This includes simple command shells, staged loaders and the YakutAgent.
  - `Encoder`: Used to encode payloads to attempt to evade detection by security software. Often works in conjunction with `Evasion` capabilities.

- **New Capability Types:**
  - `Intel`: Capabilities focused on Open Source Intelligence (OSINT) gathering, processing threat intelligence feeds and enriching target information from external sources.
  - `Recon`: Dedicated to active and passive reconnaissance, network mapping, service identification and comprehensive attack surface discovery.
  - `Delivery`: Capabilities for crafting and managing the delivery of payloads to targets (e.g., generating phishing emails with attachments, setting up malicious file servers).
  - `C2 (Command & Control)`: Capabilities for defining, configuring and managing verious Command & Control communication channels and listener types (e.g., HTTP/2, DNS over HTTPS, custom protocols). These are often used by payloads like YakutAgent.
  - `Lateral`: Specialized post-exploitation capabilities focused on techniques for moving from one compromised host to another within a target network.
  - `Evasion`: Capabilities specifically designed to bypass or mitigate various defensive measures like AV, EDR, application whitelisting or specific forensic logging.
  - `Cloud`: Capabilities tailored for interacting with and assessing cloud platforms (AWS, Azure, GCP), covering enumeration of cloud-specific vulnerabilities and post-exploitation in cloud environments.
  - `Campaign`: Advanced meta-capabilities that allow users to define and automate complex attack chains or entire campaign scenarios using a Ruby DSL, linking multiple capabilities in sequence or based on conditional logic.
  - `AISec` (Experimental): Capabilities for the security assessment of AI/ML systems (e.g., testing for model evasion, data poisoning) or leveraging AI for analyzing data collected during engagements.
