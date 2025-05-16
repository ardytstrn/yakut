# Yakut Standard Library (YSL)

The Yakut Standard Library (YSL) is a crucial component of the `Yakut::OperationsPlatform`.

- [Yakut Standard Library (YSL)](#yakut-standard-library-ysl)
  - [1. Key Categories and Contents](#1-key-categories-and-contents)
    - [1.1. Networking (`Yakut::YSL::Networking`)](#11-networking-yakutyslnetworking)
      - [1.1.1. Socket Operations](#111-socket-operations)
      - [1.1.2. HTTP/HTTPS Client](#112-httphttps-client)
      - [1.1.3. DNS Utilities](#113-dns-utilities)
      - [1.1.4. SMB/CIFS Client](#114-smbcifs-client)
      - [1.1.5. Other Protocol Clients](#115-other-protocol-clients)
    - [1.2. Data Handling \& Parsing (`Yakut::YSL::Data`)](#12-data-handling--parsing-yakutysldata)
      - [1.2.1. Encoders/Decoders](#121-encodersdecoders)
      - [1.2.2. Parsers](#122-parsers)
      - [1.2.3. String Utilities](#123-string-utilities)
      - [1.2.4. File Format Utilities](#124-file-format-utilities)
    - [1.3. Exploit Development Primitives (`Yakut::YSL::ExploitDev`)](#13-exploit-development-primitives-yakutyslexploitdev)
      - [1.3.1. Shellcode Utilities](#131-shellcode-utilities)
      - [1.3.2. Buffer Creation](#132-buffer-creation)
    - [1.4. Operating System Interaction (`Yakut::YSL::OS`)](#14-operating-system-interaction-yakutyslos)
    - [1.5. Framework Interaction Helpers (`Yakut::YSL::Framework`)](#15-framework-interaction-helpers-yakutyslframework)
      - [Logging](#logging)
      - [Reporting to `CognitionEngine`](#reporting-to-cognitionengine)
      - [Accessing Datastore](#accessing-datastore)
      - [Event Publishing (Advanced)](#event-publishing-advanced)
      - [Interacting with Current Workspace/Targets](#interacting-with-current-workspacetargets)
    - [1.6. Post-Exploitation Helpers (Primarily for `Post` Capabilities)](#16-post-exploitation-helpers-primarily-for-post-capabilities)
    - [2. Using the YSL in Your Capability](#2-using-the-ysl-in-your-capability)

## 1. Key Categories and Contents

### 1.1. Networking (`Yakut::YSL::Networking`)

#### 1.1.1. Socket Operations

- Wrappers for TCP, UDP and SSL/TLS client connections
- Helpers for sending and receiving data with timeouts and error handling
- Utilites for raw socket manipulation

#### 1.1.2. HTTP/HTTPS Client

- A robust HTTP/S client
  - Easy GET, POST, PUT, DELETE, etc. requests.
  - Cookie management.
  - Proxy support.
  - SSL/TLS certificate verification options.
  - User-Agent customization.
  - Handling redirects.
  - Support for common authentication schemes.
  - Helpers for parsing common HTTP responses (HTML, JSON, XML).

#### 1.1.3. DNS Utilities

- DNS resolution.
- Helpers for common DNS query types (A, MX, TXT, SRV).

#### 1.1.4. SMB/CIFS Client

- Helpers for connecting to SMB shares, listing files, and basic file transfers.

#### 1.1.5. Other Protocol Clients

- Simplified clients or helpers for interacting with common services like FTP, SSH (for command execution or file transfer if a library is integrated), Telnet, SNMP, etc.

### 1.2. Data Handling & Parsing (`Yakut::YSL::Data`)

#### 1.2.1. Encoders/Decoders

- Base64, hex, URL encoding/decoding.
- Common hashing functions (MD5, SHA1, SHA256, etc.).

#### 1.2.2. Parsers

- JSON, XML, CSV parsing and generation.
- HTML parsing with helpers for extracting links, forms, comments.
- Configuration file parsers.
- User-Agent string parsing.
- URL parsing and manipulation.

#### 1.2.3. String Utilities

- Random string/hex/alphanumeric generation.
- Common string manipulation tasks relevant to exploit development or data processing.

#### 1.2.4. File Format Utilities

- Helpers for identifying common file types (magic bytes).

### 1.3. Exploit Development Primitives (`Yakut::YSL::ExploitDev`)

#### 1.3.1. Shellcode Utilities

- Helpers for handling shellcode (e.g., prepending NOPs, checking for bad characters).

#### 1.3.2. Buffer Creation

- Utilities for creating patterned buffers.

### 1.4. Operating System Interaction (`Yakut::YSL::OS`)

- Local system information
- File system utilities

### 1.5. Framework Interaction Helpers (`Yakut::YSL::Framework`)

These are crucial for how Capabilities integrate with the Yakut ecosystem.

#### Logging

- `print_status`
- `print_good`
- `print_error`
- `print_warning`
- `print_debug`

#### Reporting to `CognitionEngine`

- `report_host(ip:, hostname:, os: tags:, notes:)`
- `report_service(host:, port:, proto:, name:, banner:, product:, version:)`
- `report_vuln(host:, service:, name:, cve:, risk:, description:, proof:)`
- `report_loot(host:, type:, service:, user:, secret:, data:, file_path:, notes:, source_capability_refname:)`
- `report_credential(host:, service:, user:, secret:, type: 'password'|'hash'|'key', notes:)`

#### Accessing Datastore

While `datastore` is directly available, YSL might provide helpers for common datastore
interactions or type conversions if needed.

#### Event Publishing (Advanced)

- `publish_event(topic, payload)`

#### Interacting with Current Workspace/Targets

- `current_workspace`
- `current_targets`
- `each_host(rhosts_option_value) do |ip_address| ... end`

### 1.6. Post-Exploitation Helpers (Primarily for `Post` Capabilities)

- Session interaction wrappers
- Common post-exploitation tasks

### 2. Using the YSL in Your Capability

When you write a capability by inheriting from a Yakut base class, many YSL methods
will be directly available to you as instance methods.

```ruby
class YakutCapability < Yakut::Capability::Recon
  def initialize(info = {})
    super(...))

    option :RHOSTS do
      type :address_range
      description "The target address(es), range(s) or CIDR identifier(s)"
      required true
    end
  end

  def run
    print_status("Starting reconnaissance...")

    each_host(datastore['RHOSTS']) do |host_ip|
      print_debug("Processing host: #{host_ip}")
      begin
        # Using a YSL networking helper
        http_client = Yakut::YSL::Networking::HttpClient.new(host_ip, 80, framework_context: self) # Pass context for logging/config
        response = http_client.get('/')

        if response && response.code == 200
          print_good("#{host_ip}: Found web server.")
          # Using a YSL framework interaction helper
          report_service(host: host_ip, port: 80, proto: 'tcp', name: 'http', banner: response.headers['server'])

          # Using a YSL data parsing helper
          title = Yakut::YSL::Data::HtmlParser.extract_title(response.body)
          report_note(host: host_ip, data: "Web title: #{title}") if title
        end
      rescue Yakut::YSL::Networking::ConnectionError => e
        print_error("#{host_ip}: Connection failed - #{e.message}")
      end
    end
  end
end
```
