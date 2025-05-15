# CLI Overview: The Yakut Console

The Yakut Console is the primary interface for interacting with the Yakut framework.

- [CLI Overview: The Yakut Console](#cli-overview-the-yakut-console)
- [1. Launching the Console](#1-launching-the-console)
- [2. The Command Prompt](#2-the-command-prompt)
    - [Global Context](#global-context)
    - [Workspace Context](#workspace-context)
    - [Capability Context](#capability-context)
    - [Session Context](#session-context)
- [3. Basic Navigation \& Interaction](#3-basic-navigation--interaction)
- [4. Output Structure](#4-output-structure)

# 1. Launching the Console

As covered in the [Getting Started Guide](../getting-started/first-run.md#launching-the-yakut-console), you typically launch the console using:

```bash
yakut-console
```

Upon launching, you'll be greeted by the Yakut banner and the command prompt.

# 2. The Command Prompt

The Yakut command prompt is designed to be context-aware.

### Global Context

```bash
yakut >
```

Indicates you are at the top level of the framework, not actively working within a specific module or session.

### Workspace Context

```bash
yakut [ws:my_project] >
```

Indicates that the workspace named "my_project" is currently active. All data operations (targets, loot) will be scoped to this workspace.

### Capability Context

```bash
yakut [exploit/multi/http/yakut_web_rce] >
```

Indicates that you have loaded the `exploit/multi/http/yakut_web_rce` capability.

### Session Context

```bash
yakut [session:1 (10.0.0.5:ruby_agent)] >
```

Indicates you are actively interacting with session `1`, connected to `10.0.0.5` via the
`ruby_agent`. Commands will be interpreted by the session handler.

# 3. Basic Navigation & Interaction

- **Command History:**
  - Use the <kbd>Up Arrow</kbd> and <kbd>Down Arrow</kbd> keys to cycle through previous commands.
  - The `history` command displays a list of recent commands.
- **Tab Completion:**
  - Commands and sub-commands (e.g. `module <TAB>` might show `search`, `use`, `info`).
  - Capability names (e.g. `cap use exploit/multi/http/<TAB>`).
  - Option names for loaded capabilities (e.g. `options set RHO<TAB>` might complete to `RHOSTS`).
  - File and directory paths.
- **Getting Help:**
  - `help`: Displays a general list of available commands
  - `help <command_name>`: Provides detailed help for a specific command (e.g., `help cap use`)
  - `? <command_name>`: An alias for `help`
  - Within a capability context, `info` displays detailed information about the loaded capability
- **Exiting Yakut:**
  - `exit`
  - `quit`

# 4. Output Structure

Yakut strives to provide clear, structured and useful output.

- **Status Messages:**
  - `[*]`: Informational message
  - `[+]`: Success message
  - `[-]`: Error message
  - `[!]`: Warning message
  - `[>]`: Debug message (visible when debug logging is enabled)
- **Tables:** Many commands that lists data (e.g. `capability search`, `options list`, `sessions list` will use well-formatted tables)

---

This overview should give you a good feel for the Yakut console. The best way to learn is
by doing. As you proceed through the User Guide, you'll become more familiar with these
features and the specific commands detailed in [Core Concepts](./core-concepts.md).
