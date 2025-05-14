# FAQ & Troubleshooting

## 1. Frequently Asked Questions (FAQ)

---

#### 1.1. What is Yakut?

Yakut is an open-source, Ruby-powered penetration testing framework designed for
exploit development, vulnerability assessment and advanced security research. For a
detailed preview, please see our [Introduction](./README.md#11-what-is-yakut).

---

#### 1.2. Why was Yakut created? What makes it different?

Yakut was created to provide a modern, flexible and Ruby-idiomatic alternative
in the landscape of penetration testing frameworks.

#### 1.3. What is the current development status of Yakut?

Yakut is currently in the **Pre-Alpha** stage. This means core functionalities are
under active development and subject to change. It is not yet recommended for use in
live production engagements.

#### 1.4. Is Yakut free and open-source?

Yes, Yakut is, and will always be, free and open-source software, distributed under
the [MIT License](../LICENSE.md).

#### 1.5. How does Yakut compare to Metasploit or other frameworks?

Yakut draws inspiration from established frameworks like Metasploit but aims to
innovate in areas such as module categorization, CLI usability, API design, and by
deeply leveraging modern Ruby features. While Metasploit is a mature and incredibly
comprehensive platform, Yakut hopes to offer a fresh perspective and a highly
developer-friendly environment, particularly for those comfortable with Ruby. Direct
feature-by-feature comparisons will be more relevant as Yakut matures.

## 2. Installation Troubleshooting

#### 2.1. I can't install a specific Ruby version (e.g. 3.4.3)

- **Symptoms:** `rbenv install <version>` or `rvm install <version>` fails with compilation error
- **Solutions:**
  1. On macOS with Apple Silicon, you might need to specify paths for certain libraries (e.g. OpenSSL installed via Homebrew).
  2. Ensure your version manager (`rbenv`, `rvm`) and its build components (`ruby-build`) are updated to the latest version.
  3. Check for any specific error messages during compilation – they often point to the missing dependency.

#### 2.2. `ruby` command not found, or it runs the system Ruby instead of the rbenv/RVM managed version

- **Symptoms:**
  - `ruby -v` shows an old version or "command not found".
  - `which ruby` points to `/usr/bin/ruby` instead of `~/.rbenv/shims/ruby` (for rbenv).
- **Solutions:**
  1. Ensure the `eval "$(rbenv init - <your_shell>)"` (for rbenv) is correctly added to your shell's configuration file.
  2. Shell configuration changes often require a new terminal session to take effect. Alternatively, source your profile: `source ~/.zshrc` (for zsh).
  3. Make sure you've set a Ruby version for rbenv/RVM to use. Check with `rbenv version` or `rvm list`.

## 3. Configuration Troubleshooting

SOON

## 4. Usage Troubleshooting (CLI & Modules)

SOON

## 5. Module Development Troubleshooting

SOON

## 6. Security & Ethical Use

#### 6.1. Is it legal to use Yakut?

Yakut, like any penetration testing tool, is a powerful instrument that can be used for
both ethical and unethical purposes. **It is only legal and ethical to use Yakut on systems and networks for which you have explicit, written authorization from the owner.**
Unauthorized access or attacks are illegal and carry severe consequences. Yakut's
developers and contributors are not responsible for misuse of the framework.

#### 6.2. How can I use Yakut safely for learning?

1. **Dedicated lab environment:** Set up a dedicated virtual lab environment using tools like VMware, VirtualBox or Docker.
2. **Vulnerable VMs:** Use intentionally vulnerable virtual machines as targets.
3. **Isolate your lab:** Ensure your lab network is isolated from your production network and the internet unless specifically required for a test (and you understand the risks).
4. **Never test on systems you do not own or have explicit permission to test.**

---

If your issue is not covered here, or if you believe you've found a bug in Yakut, please [open an issue](https://github.com/ardytstrn/yakut/issues) on our GitHub repository with as much detail as possible.
