# CLI Overview: The Yakut Console

The Yakut Console is the primary interface for interacting with the Yakut framework.

## 1. Launching the Console

As covered in the [Getting Started Guide](../01-getting-started/05-first-run.md#1-launching-the-yakut-console), you typically launch the console using:

```bash
yakut-console
```

Upon launching, you'll be greeted by the Yakut banner and the command prompt.

## 2. The Command Prompt

The Yakut command prompt is designed to be context-aware.

#### Global Context

```bash
yakut >
```

Indicates you are at the top level of the framework, not actively working within a specific module or session.

#### Workspace Context

```bash
yakut [ws:my_project] >
```

Indicates that the workspace named "my_project" is currently active. All data operations (targets, loot) will be scoped to this workspace.

#### Module Context

```bash
yakut [exploit/multi/http/yakut_web_rce] >
```

Indicates that you have loaded the `exploit/multi/http/yakut_web_rce` module.

#### Session Context

```bash
yakut [session:1 (10.0.0.5:ruby_agent)] >
```

Indicates you are actively interacting with session `1`, connected to `10.0.0.5` via the
`ruby_agent`. Commands will be interpreted by the session handler.

## 3. Basic Navigation & Interaction

- **Command History:**
  - Use the <kbd>Up Arrow</kbd> and <kbd>Down Arrow</kbd> keys to cycle through previous commands.
  - The `history` command displays a list of recent commands.
- **Tab Completion:**
  - Commands and sub-commands (e.g. `module <TAB>` might show `search`, `use`, `info`).
  - Module names (e.g. `module use exploit/multi/http/<TAB>`).
  - Option names for loaded modules (e.g. `options set RHO<TAB>` might complete to `RHOSTS`).
  - File and directory paths.
- **Getting Help:**
  - `help`: Displays a general list of available commands
  - `help <command_name>`: Provides detailed help for a specific command (e.g., `help module use`)
  - `? <command_name>`: An alias for `help`
  - Within a module context, `info` displays detailed information about the loaded module
- **Exiting Yakut:**
  - `exit`
  - `quit`

## 4. Output Structure

Yakut strives to provide clear, structured and useful output.

- **Status Messages:**
  - `[*]`: Informational message
  - `[+]`: Success message
  - `[-]`: Error message
  - `[!]`: Warning message
  - `[>]`: Debug message (visible when debug logging is enabled)
- **Tables:** Many commands that lists data (e.g. `module search`, `options list`, `sessions list` will use well-formatted tables)

---

This overview should give you a good feel for the Yakut console. The best way to learn is
by doing. As you proceed through the User Guide, you'll become more familiar with these
features and the specific commands detailed in [Core Concepts](./03-core-concepts.md).
