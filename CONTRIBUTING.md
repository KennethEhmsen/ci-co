# Contributing to Local CI/CD Platform

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Docker Desktop installed and running
- Node.js 18.x or 20.x
- npm 9.x or later

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/KennethEhmsen/ci-co.git
   cd ci-co
   ```

2. **Start the platform**
   ```bash
   docker compose up -d
   ```

3. **Install dependencies**
   ```bash
   cd shared && npm install && npm run build && cd ..
   cd mcp-server && npm install && npm run build && cd ..
   cd cicd-agent && npm install && npm run build && cd ..
   ```

4. **Run tests**
   ```bash
   cd shared && npm test && cd ..
   cd mcp-server && npm test && cd ..
   cd cicd-agent && npm test && cd ..
   ```

## Project Structure

```
ci-co/
├── shared/          # Shared library (handlers, config, utilities)
├── mcp-server/      # Claude Code MCP server
├── cicd-agent/      # CLI security agent
├── scripts/         # PowerShell utility scripts
└── .github/         # GitHub Actions and templates
```

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists in [GitHub Issues](https://github.com/KennethEhmsen/ci-co/issues)
2. If not, create a new issue using the **Bug Report** template
3. Include:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Node.js version, Docker version)

### Suggesting Features

1. Check existing issues and discussions
2. Create a new issue using the **Feature Request** template
3. Describe the use case and proposed solution

### Submitting Changes

1. **Fork the repository**

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Run tests**
   ```bash
   npm test
   ```

5. **Commit your changes**
   ```bash
   git commit -m "Add: brief description of changes"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**
   - Use a clear, descriptive title
   - Reference any related issues
   - Describe your changes

## Code Style

### TypeScript

- Use TypeScript for all new code
- Enable strict mode
- Use meaningful variable and function names
- Add JSDoc comments for public APIs

### Commit Messages

Use conventional commit format:

```
type: brief description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `chore`: Maintenance tasks

### Testing

- Write unit tests for new functionality
- Maintain test coverage above 80%
- Use descriptive test names
- Mock external dependencies

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## Questions?

If you have questions, feel free to:
- Open a [GitHub Discussion](https://github.com/KennethEhmsen/ci-co/discussions)
- Create an issue with the `question` label

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
