# Installation

This guide details how to install Yakut form its source code repository.

**Ensure you have met all [Prerequisites](./prerequisites.md) before proceeding.**

## Steps

### 1. Clone the Yakup Repository

Open your terminal and navigate to the directory where you want to clone the Yakut
project. Then, run the following command:

```bash
git clone https://github.com/ardytstrn/yakut.git
```

This will create a `yakut` directory containing the project's source code.

### 2. Navigate to the Project Repository

```bash
cd yakut
```

### 3. Install Ruby Dependencies with Bundler

Yakut uses Bundler to manage its required Ruby gems. Run the following command to
install all necessary dependencies:

```bash
bundle install
```

This command will read the `Gemfile` in the project root and install all listed gems.
This might take a few minutes, especially the first time, as some gems may need to be
compiled.

- **Troubleshooting Gem Installation:**
  - If you encounter any errors during this step, they are often related to missing development headers for C extensions.
  - Ensure your Ruby version manager (rbenv, RVM) is correctly set up and you are using the intended Ruby version.
  - Specific error messages will usually point towards the missing library or tool.

### 4. Verifying Installation

While there isn't a universal check until you run the console, ensuring `bundle install`
completes without errors is a good sign.

With these steps completed, Yakut's core files and dependencies should be installed
on your system.
