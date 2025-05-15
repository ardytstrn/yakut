# Working with Modules

Modules are the heart of Yakut. They provide the diverse functionalities needed for
penetration testing and security research.

## 1. Understanding Module Types in Yakut

Yakut categorizes its modules to reflect the various stages and tasks involved in an
offensive security engagement. This includes enhancements to traditional module types
and introduces new, specialized categories:

- **Standard Enhanced Types:**

  - `Exploit`: Modules designed to take advantage of specific vulnerabilities to gain unauthorized access or execute code on a target system.
  - `Auxiliary`: Used for actions that don't involve direct exploitation for access, such as scanning, enumeration, fuzzing, sniffing, denial-of-service, or administrative tasks.
  - `Post`: For post-exploitation activities conducted on a compromised system.
  - `Payload`: Code that is delivered by an exploit and runs on the target system. This includes simple command shells, staged loaders and the YakutAgent.
  - `Encoder`: Used to encode payloads to attempt to evade detection by security software. Often works in conjunction with `Evasion` modules.

- **New Module Types:**
  - `Intel`: Modules focused on Open Source Intelligence (OSINT) gathering, processing threat intelligence feeds and enriching target information from external sources.
  - `Recon`: Dedicated to active and passive reconnaissance, network mapping, service identification and comprehensive attack surface discovery.
  - `Delivery`: Modules for crafting and managing the delivery of payloads to targets (e.g., generating phishing emails with attachments, setting up malicious file servers).
  - `C2 (Command & Control)`: Modules for defining, configuring and managing verious Command & Control communication channels and listener types (e.g., HTTP/2, DNS over HTTPS, custom protocols). These are often used by payloads like YakutAgent.
  - `Lateral`: Specialized post-exploitation modules focused on techniques for moving from one compromised host to another within a target network.
  - `Evasion`: Modules specifically designed to bypass or mitigate various defensive measures like AV, EDR, application whitelisting or specific forensic logging.
  - `Cloud`: Modules tailored for interacting with and assessing cloud platforms (AWS, Azure, GCP), covering enumeration of cloud-specific vulnerabilities and post-exploitation in cloud environments.
  - `Campaign`: Advanced meta-modules that allow users to define and automate complex attack chains or entire campaign scenarios using a Ruby DSL, linking multiple modules in sequence or based on conditional logic.
  - `AISec` (Experimental): Modules for the security assessment of AI/ML systems (e.g., testing for model evasion, data poisoning) or leveraging AI for analyzing data collected during engagements.

## Module Naming & Discovery Philosophy in Yakut

Yakut employs a sophisticated approach to module naming and discovery.

- **Canonical Module Paths (for Organization & Developers):** Modules are organized on the filesystem and identified by a structured path:

  - `<type>/<platform_or_category>/<specific_target_or_service>/<short_descriptive_name>`

- **Rich Metadata & Tagging (for Powerful Discovery):** Each module is accompanied by extensive metadata, including: `title`, `ref_name`, `type`, `tags`, `description`, `reliability_score`, `impact_score`, `opsec_rating`, `cleanup_available`, `privileged`.
