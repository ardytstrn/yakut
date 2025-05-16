# Capability Options

Developing user-friendly capabilities in Yakut hinges on a robust system for defining
configurable options.

## 1. Defining Options

Options are defined within the `initialize` method of your capability class. Instead
of passing arrays to a constructor, Yakut's DSL uses a block-based syntax for each
option.

```ruby
class YakutCapability < Yakut::Capability::Exploit
  def initialize(info = {})
    super(...)

    # === Define Basic Options ===
    option :RHOSTS do
      type :address_range # Using a symbolic type, maps to Yakut::Opts::AddressRange
      description "The target address(es), range(s) or CIDR identifier(s)"
      required true
    end

    option :RPORT do
      type :port
      description "The target port"
      default 80
    end

    option :TARGET_URI do
      type :string
      description "The base URI of the target application"
      default "/app/"
      validate ->(uri) { uri.start_with('/') || "must start with a slash" }
    end

    # === Define Advanced Options ===
    advanced_option :TIMEOUT do
      type :integer
      description "Connection timeout in milliseconds"
      default 5000
      validate ->(t) { t.positive? || "must be a positive integer" }
    end

    advanced_option :USE_SSL do
      type :boolean
      description "Negotiate SSL/TLS for the connection"
      default { datastore['RPORT'] == 443 }
    end
  end

  # ... rest of your capability ...
end
```

- `option :OPTION_NAME do ... end`: Defines a standard, commonly used option.
- `advanced_option :OPTION_NAME do ... end`: Defines an option that is more specialized or less frequently adjusted. These will be displayed under an "Advanced" section in the `options` command output.

## 2. Option Definition Attributes

Within the `option` or `advanced_option` block, you use the following keywords to define
its characteristics:

- `type` (Symbol or Class - Required)
  - Specifies the data of the option.
  - **Symbolic Types:** `:string`, `:boolean`, `:integer`, `:port`, `:address`, `:address_range`, `:path`, `:file`, `:directory`, `:enum`, `:regexp`. These map to underlying `Yakut::Opts::*` classes.
  - **Class Types:** You can also provide a specific `Yakut::Opts::*` class directly or a custom option class inheriting from `Yakut::Opts::Base`.
- `description` (String - Required)
- `required` (Boolean - Optional, default: `false`)
  - If `true`, the user must provide a value for this option before the capability can be run. The framework will enforce this.
- `default` (Any or Proc - Optional)
  - The default value for the option if the user does not explicitly set one.
  - The type should match the option's `type`.
  - Can be a literal value or a `Proc` (lambda) for dynamic defaults that are evaluated when the option is accessed or the capability is loaded. This allows defaults based on other options or framework state.
- `choices`: (Array - Required for `type :enum`)
  - An array of valid string values for an enumeration option. The framework will validate user input against this list.
- `validate`: (Proc - Optional)
  - A `Proc` (lambda or block) that takes the user-provided value as an argument and performs custom validation.
  - It should return `true` if the value is valid.
  - If the value is valid, it should return a `String` containing the error message, which will be displayed to the user.

## 3. Underlying Option Types

While you primarily use the DSL keywords, Yakut internally maps these to specialized
option type classes (under `Yakut::Opts::*`) for handling normalization and basic type
validation. This is mostly an internal detail but good to be aware of if creating very
custom option types.

- `:string` -> `Yakut::Opts::String`
- `:boolean` -> `Yakut::Opts::Boolean`
- `:integer` -> `Yakut::Opts::Integer`
- `:port` -> `Yakut::Opts::Port` (validates 1-65535)
- `:address` -> `Yakut::Opts::Address` (validates single IP or hostname)
- `:address_range` -> `Yakut::Opts::AddressRange` (handles IPs, hostnames, CIDR)
- `:path` -> `Yakut::Opts::Path` (general path)
- `:file` -> `Yakut::Opts::File` (path, checks for file existence)
- `:directory` -> `Yakut::Opts::Directory` (path, checks for directory existence/writability)
- `:enum` -> `Yakut::Opts::Enum` (uses `choices` array)
- `:regexp` -> `Yakut::Opts::Regexp`

## 4. Option Validation Flow

1. **Type Coercion/Normalization:** When a user sets an option, the corresponding `Yakut::Opts::*` class attempts to convert the input string to its native type.
2. **Buit-in Type Validation:** The option type performs basic validation (e.g. an integer is indeed an integer, a port is within range).
3. **Custom `validate` Proc:** If a `validate` proc is defined for the option, it is called with the normalized value. If it returns a string, that string is treated as a validation error.
4. **Required Check:** Before a capability's `run` or `check` method is invoked, the `Yakut::OperationsPlatform::ExecutionEngine` verifies that all options marked as `required true` have been set by the user.
