<div align="center">
  <h1>Yakut</h1>
  <p><strong>A dynamic and modular penetration testing framework and exploit development platform.</strong></p>
  <p><em>(Yakut is the Turkish word for Ruby)</em></p>

  <p>
    <a href="https://opensource.org/licenses/MIT">
      <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
    </a>
    <img src="https://img.shields.io/badge/Ruby-3.0%2B-red.svg" alt="Ruby Version">
  </p>
</div>

## About the Project

Yakut is an open-source penetration testing and offensive security framework currently
in its conceptual and early development state.

Our vision is to create a framework that is not just a collection of tools, but an
intelligent, extensible and developer-centric ecosystem.

We believe in leveraging the full power and elegance of the Ruby language to create
a tool that is both incredibly powerful and a pleasure to use and extend.

### Current Status: Pre-Alpha (Conceptual Design & Early Development)

Yakut is currently in its **Pre-Alpha** phase. This means:

- The core architecture and concepts, as detailed in our [documentation](./docs), are being actively designed and refined.
- Initial foundational code may be under development, but the framework is **not yet ready for general use or production engagements.**
- Many features described in the documentation are planned and present the project's aspirational goals.
- This is the perfect time for architects, developers, and security professionals to review our vision, provide feedback and get involved in shaping the future of Yakut.

## Core Components

Yakut's architecture is envisioned as an ecosystem of specialized, interconnected
components:

- **`Yakut::Kernel`**: The core runtime, managing lifecycle, events, configuration, logging, and the internal API gateway.
- **`Yakut::CognitionEngine`**: The intelligence and data hub, managing workspaces, target profiling, loot analysis, and vulnerability intelligence.
- **`Yakut::OperationsPlatform`**: The engine for action, managing Capability discovery, execution, payload generation, and session orchestration.
- **`Yakut::C2Infrastructure`**: The dynamic Command & Control fabric, handling listeners, C2 channel abstraction, and malleable C2 profiles.
- **`Yakut::CampaignOrchestrator`**: The strategic automation engine for managing complex operational workflows.
- **`Yakut::InterfaceAdapters`**: Provides user interfaces, starting with the `CLIAdapter` (Yakut Console).

For a deep dive into the architecture, please see the [Architectural Overview](./docs/developer-guide/architectural-overview.md).

## Contributing

We are excited about building a strong community around Yakut! If you're interested in
contributing ideas, feedback, documentation, or (eventually) code, please read our
**[Contributing Guide](./CONTRIBUTING.md)**.

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

<p align="center">
<em>Happy Hacking!</em>
</p>
