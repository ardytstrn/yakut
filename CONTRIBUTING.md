# Contributing to Yakut

- [Contributing to Yakut](#contributing-to-yakut)
- [1. Code of Conduct](#1-code-of-conduct)
- [2. How Can I Contribute?](#2-how-can-i-contribute)
  - [2.1. Reporting Bugs](#21-reporting-bugs)
  - [2.2. Suggesting Enhancements or New Features](#22-suggesting-enhancements-or-new-features)
  - [2.3. Contributing Code (Capabilities, Core)](#23-contributing-code-capabilities-core)
  - [2.4. Improving Documentation](#24-improving-documentation)
- [3. Setting Up Your Development Environment](#3-setting-up-your-development-environment)
- [4. Contribution Workflow](#4-contribution-workflow)
  - [4.1. Fork the Repository](#41-fork-the-repository)
  - [4.2. Create a Branch](#42-create-a-branch)
  - [4.3. Write Your Code](#43-write-your-code)
  - [4.4. Commit Your Changes](#44-commit-your-changes)
  - [4.5. Run Tests](#45-run-tests)
  - [4.6. Push to Your Branch](#46-push-to-your-branch)
  - [4.7. Open a Pull Request (PR)](#47-open-a-pull-request-pr)
- [5. Coding Standards \& Style Guide](#5-coding-standards--style-guide)
- [6. Pull Request Process](#6-pull-request-process)
- [7. Questions or Need Help?](#7-questions-or-need-help)

First off, thank you for considering contributing to Yakut! We welcome contributions from
everyone and we're excited to see how the community can help Yakut grow and improve.
Whether you're fixing a bug, proposing a new feature, improving documentation, or
developing a new Capability, your help is valuable.

This document provides guidelines for contributing to Yakut. Please take a moment to
review it to ensure a smooth and effective contribution process.

# 1. Code of Conduct

Yakut is dedicated to providing a welcoming and inclusive environment for everyone.
All participants, including contributors, maintainers and users, are expected to adhere
to our [Code of Conduct](./CODE_OF_CONDUCT.md). Please read it before participating.

# 2. How Can I Contribute?

There are many ways to contribute to Yakut:

## 2.1. Reporting Bugs

If you encounter a bug, please help us by reporting it. Good bug reports are essential
for making Yakut more stable and reliable.

- **Check Existing Issues:** Before submitting a new bug report, please search the [GitHub Issues](https://github.com/ardytstrn/yakut/issues) to see if the bug has already been reported.
- **Create a New Issue:** If the bug hasn't reported, create a new issue. Please include:
  - A clear and descriptive title.
  - Your Yakut version (`yakut-console -v`) and Ruby version (`ruby -v`).
  - Your operating system and version.
  - Detailed steps to reproduce the bug.
  - What you expected to happen.
  - What actually happened (including any error messages and relevant log snippets).
  - Screenshots or GIFs if they illustrate the issue.

## 2.2. Suggesting Enhancements or New Features

We welcome suggestions for new features or enhancements to existing ones!

- **Check Existing Issues/Discussions:** Search [GitHub Issues](https://github.com/ardytstrn/yakut/issues) and [GitHub Discussions](https://github.com/ardytstrn/yakut/discussions) to see if your idea has already been discussed.
- **Create a New Issue/Discussion:**
  - Use a clear and descriptive title.
  - Provide a detailed explanation of the proposed enhancement or feature.
  - Explain the use case: why would this be useful to Yakut users or developers?
  - If possible, provide examples of how it might work or be implemented.
  - Consider if this aligns with Yakut's core philosophy.

## 2.3. Contributing Code (Capabilities, Core)

This is one of the most direct ways to contribute. Whether it's a new Capability
(exploit, recon tool, C2 channel, etc.), a bug fix in the core, or a performance improvement,
code contributions are highly valued.

- **Find an Issue:** Look for issues tagged with `help wanted`, `good first issue` or discuss your intended contribution with the maintainers first, especially for larger features.
- **Follow the Workflow:** Adhere to the [Contribution Workflow]() outlined below.
- **Adhere to Standards:** Ensure your code follows the [Coding Standards & Style Guide]() and includes appropriate [Tests]().
- **Capability Development:** If you are developing a new Capability, please refer to the [Developer Guide - Capability Development](./docs/developer-guide/capability-development/README.md) for specific guidelines on structure, metadata and API usage.

## 2.4. Improving Documentation

Good documentation is crucial! If you find errors, omissions, or areas that could be clearer in our documentation (including this guide!), please:

- Open an issue detailing the problem.
- Or, even better, submit a pull request with your proposed changes. Documentation files are typically in Markdown format in the `/docs` directory.

# 3. Setting Up Your Development Environment

To contribute code, you'll need to set up a development environment for Yakut. See [Installation](./docs/getting-started/installation.md).

# 4. Contribution Workflow

We follow a standard GitHub fork-and-pull model.

## 4.1. Fork the Repository

Click the "Fork" button on the main [Yakut GitHub repository](https://github.com/ardytstrn/yakut) page to create your own copy.

## 4.2. Create a Branch

Create a new branch in your forked repository for your changes. Choose a descriptive
branch name (e.g., `feature/new-intel-capability`, `fix/cli-output-bug`, `docs/update-installation-guide`).

```bash
git checkout -b feature/my-awesome-capability
```

## 4.3. Write Your Code

Make your changes, write your code and add new tests for your contribution.

- Follow the [Coding Standards & Style Guide]().
- Ensure new code is well-commented, especially complex logic.
- If adding a new Capability, follow the structure and metadata guidelines in the Developer Guide.

## 4.4. Commit Your Changes

Commit your changes with clear, descriptive commit messages. We generally follow the
[Conventional Commits]() specification, but a well-written message is most important.

- A good commit message might look like:

```
feat(intel): Add Shodan host query capability

Implements a new Intel capability to query Shodan for host information
based on an IP address. Includes options for API key and history.
Adds unit tests for core logic.

Fixes #123
```

- Sign your commits

## 4.5. Run Tests

Before submitting, ensure all existing tests pass and that you've added new tests
covering your changes.

```bash
bundle exec rspec
```

## 4.6. Push to Your Branch

Push your committed changes to your forked repository on GitHub:

```bash
git push origin feature/my-awesome-capability
```

## 4.7. Open a Pull Request (PR)

Go to the original Yakut repository on GitHub and open a new Pull Request from your
forked branch to the `main` branch of the Yakut repository.

- Provide a clear title and a detailed description of your changes in the PR.
- Reference any relevant issues (e.g. "Closes #123", "Fixes #456").
- Be prepared to discuss your changes and make adjustments based on feedback from maintainers.

# 5. Coding Standards & Style Guide

To maintain code consistency and readability, Yakut adheres to the following:

- [Ruby Style Guide](): We generally follow the [Ruby Style Guide](https://github.com/rubocop/ruby-style-guide) and use [RoboCop](https://github.com/rubocop/rubocop) for automated style checking and enforcement.
- **Comments:** Write clear and concise comments for complex logic, public APIs, and non-obvious code sections. Use YARDoc format for documenting methods and classes where appropriate.
- **Naming Conventions:** Follow standard Ruby naming conventions (snake_case for methods and variables, CamelCase for classes and modules).
- **Error Handling:** Use appropriate exception handling. Avoid rescuing `Exception` broadly.
- **Security Considerations:** As a security tool, be mindful of secure coding practices in your contributions (e.g., avoid command injection if shelling out, handle user input carefully).

# 6. Pull Request Process

1. Ensure your PR addresses an existing issue or has been discussed with maintainers for new features.
2. Your PR description should clearly explain the changes and their rationale.
3. Maintainers will review your PR. Be responsive to feedback and questions.
4. Once approved, your PR will be merged by a maintainer. Congratulations, and thank you!

We aim to review PRs in a timely manner, but please be patient as this is a
community-driven project.

# 7. Questions or Need Help?

- **Documentation:** Please check these contribution guidelines and other project documentation first.
- **GitHub Issues:** For specific questions about bugs or features.
