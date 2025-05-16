# Capability Anatomy & Structure

Understanding the fundamental structure of Yakut Capability is the first step towards
developing your own.

## 1. Core Philosophy: Convention over Configuration

Yakut embraces "convention over configuration" philosophy for capability development.
This means that by following certain naming conventions and structural patterns, much
of the boilerplate for integrating your capability into the framework is handled
automatically by the `Yakut::OperationsPlatform::CapabilityRegistry`.

## 2. Base Capability Classes

All Yakut capabilities must inherit from a base class provided by the framework. This
base class provides common functionalities, defines the expected interface and integrates
the capability with Yakut's core services (via the Yakut Standard Library and direct API
address where appropiate).

The primary base class is `Yakut::Capability::Base`. However, for specific Capability
types, you will typically inherit from a more specialized base class that itself inherits
from `Yakut::Capability::Base` and adds type-specific logic or requirements.

### 2.1. `Yakut::Capability::Base`: The Most Fundamental Base Class

It provides:

- Metadata registration.
- Option registration.
- Access to the `datastore`.
- Access to the framework services like logging and methods to report loot or update target information via the `Yakut::CognitionEngine`.
- Basic lifecycle methods (`initialize`, `run`, `check`, `cleanup`)

### 2.2. `Yakut::Capability::Exploit < Yakut::Capability::Base`

It adds:

- Payload handling logic and options.
- Targeting mechanisms.
- Specific metadata fields related to exploits (e.g., `PayloadInformation`, `Targets`).

### 2.3. `Yakut::Capability::Auxiliary::Base < Yakut::Capability::Base`

- `Yakut::Capability::Auxiliary::Scanner`
- `Yakut::Capability::Auxiliary::Server`
- `Yakut::Capability::Auxiliary::Sniffer`
- And so on.

### 2.4. `Yakut::Capability::Post < Yakut::Capability::Base`

For post-exploitation capabilities.

- Requires a `session` object to be passed or available in its context.
- Provides helpers for interacting with YakutAgent sessions.

### 2.5. `Yakut::Capability::Intel < Yakut::Capability::Base`

For intelligence gathering capabilities.

- May include helpers for interacting with common OSINT APIs or parsing specific data formats.

### 2.6. `Yakut::Capability::Recon < Yakut::Capability::Base`

For reconnaissance Capabilities.

### 2.7. `Yakut::Capability::Delivery < Yakut::Capability::Base`

For payload delivery mechanisms.

### 2.8. `Yakut::Capability::C2 < Yakut::Capability::Base`

For defining C2 listeners or profiles.

### 2.9. `Yakut::Capability::LateralMovement < Yakut::Capability::Post`

Often inherits from `Post`, requires a `session.`

### 2.10. `Yakut::Capability::Evasion < Yakut::Capability::Base`

For evasion techniques.

### 2.11. `Yakut::Capability::Sustainment < Yakut::Capability::Post`

Often inherits from `Post`, for persistence.

### 2.12. `Yakut::Capability::Cloud < Yakut::Capability::Base`

Base for cloud-specific capabilities.

### 2.13. `Yakut::Capability::Orchestration < Yakut::Capability::Base`

For defining complex workflows.

## 3. Standard File Structure & Naming

Capabilities are Ruby files `.rb` residing within the `capabilities/` directory of Yakut
or in user-defined capability paths.

- **Root Directory:** `YAKUT_ROOT/capabilities/`
- **Structure:** `capabilities/<type>/<platform_or_category>/<specific_target_or_service>/<capability_file_name>.rb`

The capability with RefName `exploit/windows/smb/eternalblue_ms1701` would typically reside in:
`YAKUT_ROOT/capabilities/exploits/windows/smb/eternalblue_ms17010.rb`

## 4. Essential Methods in a Capability

While specific Capability types might introduce additional required methods, the
following are fundamental to most capabilities:

### 4.1. `initialize(info = {})` (Required)

The constructor for your capability class. This is where you define all the metadata for
your capability using the `super(...)` pattern and register its configurable options.

### 4.2. `run()` (Required for most types)

This is the main method where your Capability's primary logic resides.
When a user executes `run` (or `exploit`) in the Yakut console for your
loaded capability, this method is called.

### 4.3. `check()` ((Optional, but highly recommended for Exploits and some Auxiliary/Recon)

This method is designed to determine if a target is likely vulnerable to an exploit or
if the conditions for an auxiliary/recon Capability are met,
_without actually performing the full/destructive action_.

```ruby
def check
  # ... logic to connect and non-intrusively check for vulnerability indicators ...

  service_banner = get_banner(datastore['RHOSTS'], datastore['RPORT'])
  if service_banner && service_banner.include?("VulnerableWebServer 1.0")
    return Yakut::CheckCode::AppearsVulnerable
  end

  return Yakut::CheckCode::AppearsSafe
end
```

### 4.4. `cleanup()` (Optional, but important for Capabilities that make changes)

- **Purpose:** If your Capability makes changes to the target system (e.g., creates files, modifies registry keys, starts services for persistence) or to the Yakut framework's state (e.g., starts a listener that needs to be stopped), this method should implement the logic to revert those changes.
- **When Called:** The framework might call this automatically upon session closure, exploit completion, or via a manual `cleanup` command from the user (if implemented).

```ruby
def cleanup
  if @created_file_path
    delete_remote_file(@created_file_path)
    print_good("Cleaned up: #{created_file_path}")
  end
end
```

## 5. The `datastore`

Within your capability instance, `datastore` is a hash-like object that holds the current
values of all registered options (both global options inherited by the Capability and
options specific to it).

You access option values like `datastore['RHOSTS']`. Values set by the user via `set OPTION_NAME value`
are reflected in the `datastore`.

## 6. Yakut Standard Library (YSL) and Core API Access

- Your capability will have access to the YSL.
- It can also interact with core framework services (e.g., for logging, reporting loot, managing sessions) through a well-defined internal API.
