# Prerequisites

Before you can install and run Yakut, please ensure your system meets the
following requirements:

## 1. Ruby Environment

- **Ruby:** Yakut is built with Ruby. We recommend using the **latest stable version of Ruby (currently 3.4+ is targeted)**.

  - It is highly recommended to manage your Ruby versions using a version manager like:
    - **rbenv** - [rbenv Website](https://rbenv.org/)
    - **RVM** (Ruby Version Manager) - [RVM Website](https://rvm.io/)
    - **asdf** (with the Ruby plugin) - [asdf Website](https://asdf-vm.com/)
  - Using a version manager avoids conflicts with the system Ruby (if present on macOS or Linux) and allows you to switch between Ruby versions easily.
  - _Avoid using the system-installed Ruby for development._

- **Bundler:** Bundler is the standard Ruby dependency manager.
  - Install Bundler (if you don't have it already) after setting up your Ruby:

```bash
gem install bundler
```

## 2. Version Control

- **Git:** You will need Git to clone the Yakut repository.
  - Most systems have Git pre-installed. You can check with `git --version`.
  - If not, download it from [git-scm.com](https://git-scm.com/downloads).

## 3. Build Tools

Ruby and some of its gems are written in C or require C extensions to be compiled during
installation. Therefore, you need a proper build environment.

---

Once you have confirmed these prerequisites, you can proceed to **[Installation](./03-installation.md)**.
