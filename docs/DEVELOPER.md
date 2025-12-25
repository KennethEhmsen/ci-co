# Developer Guide

This guide explains how to extend and modify the CI/CD Security Platform.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Development Setup](#development-setup)
- [Adding New Tools](#adding-new-tools)
- [Adding New Handlers](#adding-new-handlers)
- [Adding MCP Resources](#adding-mcp-resources)
- [Testing](#testing)
- [Type Definitions](#type-definitions)
- [Code Style](#code-style)
- [Build and Release](#build-and-release)

---

## Architecture Overview

The platform follows a layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│                     Consumers                           │
│  ┌─────────────────┐        ┌─────────────────┐        │
│  │   MCP Server    │        │   CI/CD Agent   │        │
│  │  (Claude Code)  │        │     (CLI)       │        │
│  └────────┬────────┘        └────────┬────────┘        │
│           │                          │                  │
│           └──────────┬───────────────┘                  │
│                      ▼                                  │
│  ┌─────────────────────────────────────────────────┐   │
│  │              @cicd/shared                        │   │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────────────┐  │   │
│  │  │Handlers │ │Validation│ │   HTTP Client    │  │   │
│  │  └─────────┘ └──────────┘ └──────────────────┘  │   │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────────────┐  │   │
│  │  │ Config  │ │  Types   │ │      Utils       │  │   │
│  │  └─────────┘ └──────────┘ └──────────────────┘  │   │
│  └─────────────────────────────────────────────────┘   │
│                      │                                  │
│                      ▼                                  │
│  ┌─────────────────────────────────────────────────┐   │
│  │            External Services                     │   │
│  │  Gitea │ Drone │ SonarQube │ D-Track │ Trivy   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Key Principles

1. **Shared Library First**: All business logic lives in `@cicd/shared`
2. **Thin Consumers**: MCP Server and Agent are thin wrappers
3. **Single Source of Truth**: Tool definitions are defined once
4. **Type Safety**: TypeScript throughout with strict mode

---

## Project Structure

```
ci-co/
├── shared/                     # @cicd/shared - Core library
│   ├── src/
│   │   ├── index.ts           # Public exports
│   │   ├── config.ts          # Configuration loader
│   │   ├── handlers.ts        # API handlers
│   │   ├── validation.ts      # Input validation
│   │   ├── http.ts            # HTTP utilities
│   │   ├── types.ts           # Type definitions
│   │   └── index.test.ts      # Tests
│   ├── package.json
│   └── tsconfig.json
│
├── mcp-server/                 # MCP Server for Claude Code
│   ├── src/
│   │   ├── index.ts           # Server entry point
│   │   ├── handlers.ts        # Re-exported handlers
│   │   ├── handlers.test.ts   # Handler tests
│   │   └── index.test.ts      # Server tests
│   ├── package.json
│   └── tsconfig.json
│
├── cicd-agent/                 # CLI Agent
│   ├── src/
│   │   ├── index.ts           # CLI entry point
│   │   ├── tools.ts           # Tool definitions
│   │   ├── tools.test.ts      # Tool tests
│   │   └── index.test.ts      # Agent tests
│   ├── package.json
│   └── tsconfig.json
│
├── scripts/                    # Installation scripts
├── docs/                       # Documentation
├── .github/                    # GitHub workflows
├── docker-compose.yml          # Infrastructure
├── package.json                # Root workspace config
└── .env.example                # Environment template
```

---

## Development Setup

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0
- Docker Desktop (for running services)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/KennethEhmsen/ci-co.git
cd ci-co

# Install dependencies (all workspaces)
npm install

# Build all packages
npm run build

# Run tests
npm test
```

### Development Workflow

```bash
# Watch mode for shared library
cd shared && npm run dev

# In another terminal, watch the package you're working on
cd mcp-server && npm run dev
# or
cd cicd-agent && npm run dev
```

### Code Quality

```bash
# Lint all packages
npm run lint

# Fix lint issues
npm run lint:fix

# Format code
npm run format

# Check formatting
npm run format:check
```

---

## Adding New Tools

To add a new tool to the platform, follow these steps:

### Step 1: Add Handler to Shared Library

Edit `shared/src/handlers.ts`:

```typescript
// =============================================================================
// Your New Integration
// =============================================================================

/**
 * Fetch data from your new service
 * @param param1 - Description of parameter
 * @returns Promise with the response data
 */
export async function myServiceGetData(param1: string): Promise<MyServiceResponse> {
  if (!config.myService.apiKey) {
    throw new Error("MyService API key not configured. Set MY_SERVICE_API_KEY environment variable.");
  }

  return fetchJson(`${config.myService.url}/api/data/${param1}`, {
    headers: { "Authorization": `Bearer ${config.myService.apiKey}` },
  });
}
```

### Step 2: Export from Shared Index

Edit `shared/src/index.ts`:

```typescript
// Add to exports
export {
  // ... existing exports ...
  myServiceGetData,
} from "./handlers.js";
```

### Step 3: Add Tool Definition to Agent

Edit `cicd-agent/src/tools.ts`:

```typescript
// Add to toolHandlers map
const toolHandlers: Record<string, ToolHandler> = {
  // ... existing handlers ...

  // My Service
  my_service_get_data: async (input) => myServiceGetData(input.param1 as string),
};

// Add to tools array
export const tools: Anthropic.Tool[] = [
  // ... existing tools ...

  // My Service Tools
  {
    name: "my_service_get_data",
    description: "Fetch data from My Service",
    input_schema: {
      type: "object" as const,
      properties: {
        param1: {
          type: "string",
          description: "The parameter to fetch",
        },
      },
      required: ["param1"],
    },
  },
];
```

### Step 4: Add Tool to MCP Server

Edit `mcp-server/src/index.ts`:

```typescript
// Import the handler
import { myServiceGetData } from "./handlers.js";

// Add tool definition to TOOLS array
const TOOLS = [
  // ... existing tools ...
  {
    name: "my_service_get_data",
    description: "Fetch data from My Service",
    inputSchema: {
      type: "object",
      properties: {
        param1: {
          type: "string",
          description: "The parameter to fetch",
        },
      },
      required: ["param1"],
    },
  },
];

// Add handler in CallToolRequestSchema handler
case "my_service_get_data":
  return myServiceGetData(args.param1 as string);
```

### Step 5: Add Configuration

Edit `shared/src/config.ts`:

```typescript
export const config = {
  // ... existing config ...

  myService: {
    url: process.env.MY_SERVICE_URL || "http://localhost:8090",
    apiKey: process.env.MY_SERVICE_API_KEY || "",
  },
};
```

Update `.env.example`:

```bash
# My Service
MY_SERVICE_URL=http://localhost:8090
MY_SERVICE_API_KEY=your-api-key
```

### Step 6: Add Tests

Create tests in the appropriate test files:

```typescript
// shared/src/index.test.ts
describe("myServiceGetData", () => {
  it("should fetch data successfully", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ data: "test" }),
    });

    const result = await myServiceGetData("test-param");
    expect(result).toEqual({ data: "test" });
  });
});
```

### Step 7: Add Types

Edit `shared/src/types.ts`:

```typescript
// =============================================================================
// My Service Types
// =============================================================================

export interface MyServiceResponse {
  data: string;
  metadata?: {
    timestamp: string;
  };
}
```

### Step 8: Document the Tool

Update `docs/API.md` with the new tool documentation.

---

## Adding New Handlers

Handlers are the core business logic that interact with external services.

### Handler Pattern

```typescript
/**
 * Handler function template
 *
 * @param requiredParam - A required parameter
 * @param optionalParam - An optional parameter with default
 * @returns Promise resolving to the API response
 * @throws Error if validation fails or API call fails
 */
export async function serviceActionName(
  requiredParam: string,
  optionalParam: string = "default"
): Promise<ResponseType> {
  // 1. Validate inputs
  const safeParam = validateInput(requiredParam);
  if (!safeParam) {
    throw new Error("Invalid parameter provided");
  }

  // 2. Check configuration
  if (!config.service.apiKey) {
    throw new Error("Service API key not configured.");
  }

  // 3. Make API call
  try {
    return await fetchJson(`${config.service.url}/api/endpoint`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${config.service.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ param: safeParam }),
    });
  } catch (error: any) {
    // 4. Handle errors gracefully
    if (error.response) {
      return { error: error.message, details: error.response };
    }
    throw error;
  }
}
```

### Validation Helpers

Use the validation utilities from `validation.ts`:

```typescript
import { validateSeverity, sanitizePath, sanitizeImageName } from "./validation.js";

// Path validation (removes path traversal attempts)
const safePath = sanitizePath(userPath);

// Image name validation (removes shell metacharacters)
const safeImage = sanitizeImageName(imageName);

// Severity validation (ensures valid severity levels)
const safeSeverity = validateSeverity(severity);
```

---

## Adding MCP Resources

MCP Resources provide read-only data to Claude Code.

### Resource Pattern

Edit `mcp-server/src/index.ts`:

```typescript
// Add to RESOURCES array
const RESOURCES = [
  // ... existing resources ...
  {
    uri: "cicd://my-resource",
    name: "My Resource",
    description: "Description of what this resource provides",
    mimeType: "application/json",
  },
];

// Handle in ReadResourceRequestSchema handler
case "cicd://my-resource":
  return {
    contents: [{
      uri: request.params.uri,
      mimeType: "application/json",
      text: JSON.stringify(await getMyResourceData(), null, 2),
    }],
  };
```

---

## Testing

### Test Structure

Each package has its own test file(s):

- `shared/src/index.test.ts` - Core library tests
- `mcp-server/src/index.test.ts` - Server integration tests
- `mcp-server/src/handlers.test.ts` - Handler unit tests
- `cicd-agent/src/index.test.ts` - Agent tests
- `cicd-agent/src/tools.test.ts` - Tool execution tests

### Running Tests

```bash
# All packages
npm test

# With coverage
npm run test:coverage

# Single package
cd shared && npm test
cd mcp-server && npm test
cd cicd-agent && npm test

# Watch mode
npm test -- --watch
```

### Mocking External Services

```typescript
import { vi, describe, it, expect, beforeEach } from "vitest";

describe("myHandler", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("should handle successful response", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ data: "success" }),
    });

    const result = await myHandler("param");
    expect(result).toEqual({ data: "success" });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/endpoint"),
      expect.any(Object)
    );
  });

  it("should handle API errors", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
    });

    await expect(myHandler("param")).rejects.toThrow("Not Found");
  });
});
```

### Mocking Exec for Trivy Tests

```typescript
vi.mock("node:util", async (importOriginal) => {
  const original = await importOriginal() as any;
  return {
    ...original,
    promisify: (_fn: any) => {
      return async (..._args: any[]) => {
        const mockExecResult = (global as any).__mockExecResult;
        if (mockExecResult?.error) {
          throw mockExecResult.error;
        }
        return mockExecResult || { stdout: "{}", stderr: "" };
      };
    },
  };
});

// In test
(global as any).__mockExecResult = {
  stdout: JSON.stringify({ Results: [] }),
  stderr: "",
};
```

---

## Type Definitions

### Adding Types

Edit `shared/src/types.ts`:

```typescript
// =============================================================================
// Service Name Types
// =============================================================================

/**
 * Response from the service API
 */
export interface ServiceResponse {
  /** Unique identifier */
  id: string;

  /** Display name */
  name: string;

  /** Optional metadata */
  metadata?: ServiceMetadata;
}

/**
 * Metadata associated with a service response
 */
export interface ServiceMetadata {
  /** When the data was created */
  createdAt: string;

  /** When the data was last updated */
  updatedAt: string;
}
```

### Using Types

```typescript
import type { ServiceResponse } from "./types.js";

export async function getServiceData(): Promise<ServiceResponse> {
  // Implementation
}
```

---

## Code Style

### ESLint Configuration

The project uses ESLint with TypeScript support. Key rules:

- No explicit `any` (warning)
- No unused variables (error, except `_` prefixed)
- Consistent code formatting via Prettier

### Prettier Configuration

```json
{
  "semi": true,
  "singleQuote": false,
  "tabWidth": 2,
  "trailingComma": "es5",
  "printWidth": 100
}
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Functions | camelCase, verb prefix | `getUserData`, `createRepo` |
| Variables | camelCase | `userName`, `repoList` |
| Constants | UPPER_SNAKE_CASE | `DEFAULT_TIMEOUT`, `API_VERSION` |
| Types/Interfaces | PascalCase | `UserData`, `RepoResponse` |
| Files | kebab-case or camelCase | `handlers.ts`, `index.test.ts` |

---

## Build and Release

### Building

```bash
# Build all packages
npm run build

# Build specific package
cd shared && npm run build
```

### Version Bumping

Update version in all `package.json` files:
- `package.json` (root)
- `shared/package.json`
- `mcp-server/package.json`
- `cicd-agent/package.json`

### Creating a Release

1. Update `CHANGELOG.md` with changes
2. Bump versions in all package.json files
3. Commit: `git commit -m "Bump version to X.Y.Z"`
4. Tag: `git tag vX.Y.Z`
5. Push: `git push && git push --tags`
6. GitHub will create a release automatically

### Pre-release Checklist

- [ ] All tests pass (`npm test`)
- [ ] Lint passes (`npm run lint`)
- [ ] Build succeeds (`npm run build`)
- [ ] CHANGELOG.md updated
- [ ] Version numbers updated
- [ ] Documentation updated
