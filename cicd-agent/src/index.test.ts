import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import Anthropic from '@anthropic-ai/sdk';

/** Mock Anthropic client interface */
interface MockAnthropicClient {
  messages: {
    create: Mock;
  };
}

/** Mock message structure */
interface MockMessage {
  role: string;
  content: string | Array<{ type: string; tool_use_id?: string }>;
}

// Mock dotenv first
vi.mock('dotenv', () => ({
  config: vi.fn(),
}));

// Mock tools module
vi.mock('./tools.js', async (importOriginal) => {
  const original = await importOriginal() as Record<string, unknown>;
  return {
    ...original,
    executeTool: vi.fn().mockResolvedValue('{"result": "success"}'),
  };
});

// Mock the Anthropic SDK with a class
vi.mock('@anthropic-ai/sdk', () => {
  class MockAnthropic {
    messages = {
      create: vi.fn(),
    };
  }
  return {
    default: MockAnthropic,
  };
});

// Import after mocks are set up
import {
  CICDSecurityAgent,
  SYSTEM_PROMPT,
  tools,
  executeTool,
  handleScanCommand,
  handleScanImageCommand,
  handleStatusCommand,
  handleReposCommand,
  handleBuildsCommand,
  handleSecurityReportCommand,
  handleMigrateCommand,
  handleAskCommand,
} from './index.js';

// =============================================================================
// SYSTEM_PROMPT Tests
// =============================================================================

describe('SYSTEM_PROMPT', () => {
  it('should be defined', () => {
    expect(SYSTEM_PROMPT).toBeDefined();
  });

  it('should contain security scanning information', () => {
    expect(SYSTEM_PROMPT).toContain('Security Scanning');
    expect(SYSTEM_PROMPT).toContain('Trivy');
    expect(SYSTEM_PROMPT).toContain('SonarQube');
    expect(SYSTEM_PROMPT).toContain('Dependency-Track');
  });

  it('should contain Git operations information', () => {
    expect(SYSTEM_PROMPT).toContain('Git Operations');
    expect(SYSTEM_PROMPT).toContain('Gitea');
  });

  it('should contain CI/CD pipeline information', () => {
    expect(SYSTEM_PROMPT).toContain('CI/CD Pipelines');
    expect(SYSTEM_PROMPT).toContain('Drone CI');
  });

  it('should contain Docker Registry information', () => {
    expect(SYSTEM_PROMPT).toContain('Docker Registry');
  });

  it('should contain platform URLs', () => {
    expect(SYSTEM_PROMPT).toContain('localhost:3000');
    expect(SYSTEM_PROMPT).toContain('localhost:8085');
    expect(SYSTEM_PROMPT).toContain('localhost:9000');
    expect(SYSTEM_PROMPT).toContain('localhost:8082');
  });
});

// =============================================================================
// Tools Export Tests
// =============================================================================

describe('tools export', () => {
  it('should export tools array', () => {
    expect(tools).toBeDefined();
    expect(Array.isArray(tools)).toBe(true);
  });

  it('should contain expected tool definitions', () => {
    const toolNames = tools.map((t: { name: string }) => t.name);
    expect(toolNames).toContain('trivy_scan_path');
    expect(toolNames).toContain('trivy_scan_image');
    expect(toolNames).toContain('sonar_list_projects');
    expect(toolNames).toContain('gitea_list_repos');
    expect(toolNames).toContain('drone_list_repos');
  });
});

describe('executeTool export', () => {
  it('should export executeTool function', () => {
    expect(executeTool).toBeDefined();
    expect(typeof executeTool).toBe('function');
  });
});

// =============================================================================
// CICDSecurityAgent Tests
// =============================================================================

describe('CICDSecurityAgent', () => {
  let mockClient: MockAnthropicClient;
  let mockCreate: Mock;

  beforeEach(() => {
    vi.clearAllMocks();
    mockCreate = vi.fn();
    mockClient = {
      messages: {
        create: mockCreate,
      },
    };
  });

  describe('constructor', () => {
    it('should create agent with default client', () => {
      const agent = new CICDSecurityAgent();
      expect(agent).toBeDefined();
    });

    it('should create agent with injected client', () => {
      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      expect(agent).toBeDefined();
    });
  });

  describe('getConversationHistory', () => {
    it('should return empty array initially', () => {
      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      expect(agent.getConversationHistory()).toEqual([]);
    });

    it('should return copy of conversation history', () => {
      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      const history1 = agent.getConversationHistory();
      const history2 = agent.getConversationHistory();
      expect(history1).not.toBe(history2);
    });
  });

  describe('resetConversation', () => {
    it('should clear conversation history', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Hello!' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      await agent.chat('Hi');
      expect(agent.getConversationHistory().length).toBeGreaterThan(0);

      agent.resetConversation();
      expect(agent.getConversationHistory()).toEqual([]);
    });
  });

  describe('chat', () => {
    it('should handle simple text response', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Hello! How can I help you?' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      const response = await agent.chat('Hello');

      expect(response).toBe('Hello! How can I help you?');
      expect(mockCreate).toHaveBeenCalledTimes(1);
    });

    it('should add user message to conversation history', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Response' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      await agent.chat('Test message');

      const history = agent.getConversationHistory();
      expect(history[0]).toEqual({ role: 'user', content: 'Test message' });
    });

    it('should add assistant response to conversation history', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Response' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      await agent.chat('Test');

      const history = agent.getConversationHistory();
      expect(history.length).toBe(2);
      expect(history[1].role).toBe('assistant');
    });

    it('should return default message when no text content', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      const response = await agent.chat('Test');

      expect(response).toBe('No response generated.');
    });

    it('should handle tool use in response', async () => {
      // First response with tool use
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'tool_use',
        content: [
          {
            type: 'tool_use',
            id: 'tool_1',
            name: 'gitea_list_repos',
            input: {},
          },
        ],
      });

      // Second response after tool execution
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Here are the repositories.' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      const response = await agent.chat('List repos');

      expect(response).toBe('Here are the repositories.');
      expect(mockCreate).toHaveBeenCalledTimes(2);
      expect(executeTool).toHaveBeenCalledWith('gitea_list_repos', {});
    });

    it('should handle multiple tool uses', async () => {
      // First response with multiple tool uses
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'tool_use',
        content: [
          { type: 'tool_use', id: 'tool_1', name: 'gitea_list_repos', input: {} },
          { type: 'tool_use', id: 'tool_2', name: 'drone_list_repos', input: {} },
        ],
      });

      // Final response
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Found both.' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      const response = await agent.chat('List all');

      expect(response).toBe('Found both.');
      expect(executeTool).toHaveBeenCalledTimes(2);
    });

    it('should include system prompt in API call', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Response' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      await agent.chat('Test');

      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          system: SYSTEM_PROMPT,
        })
      );
    });

    it('should include tools in API call', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Response' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      await agent.chat('Test');

      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          tools: tools,
        })
      );
    });

    it('should use correct model', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Response' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      await agent.chat('Test');

      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          model: 'claude-sonnet-4-20250514',
        })
      );
    });

    it('should set max_tokens', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Response' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      await agent.chat('Test');

      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          max_tokens: 8096,
        })
      );
    });
  });

  describe('runSingleQuery', () => {
    it('should call chat with query', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Query response' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      const response = await agent.runSingleQuery('Single query');

      expect(response).toBe('Query response');
    });
  });

  describe('agentic loop', () => {
    it('should continue until stop_reason is not tool_use', async () => {
      // First tool use
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'tool_use',
        content: [{ type: 'tool_use', id: 'tool_1', name: 'gitea_list_repos', input: {} }],
      });

      // Second tool use
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'tool_use',
        content: [{ type: 'tool_use', id: 'tool_2', name: 'drone_list_repos', input: {} }],
      });

      // Final text response
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'All done!' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      const response = await agent.chat('Do multiple things');

      expect(response).toBe('All done!');
      expect(mockCreate).toHaveBeenCalledTimes(3);
    });

    it('should pass tool results back to the model', async () => {
      mockCreate.mockResolvedValueOnce({
        stop_reason: 'tool_use',
        content: [{ type: 'tool_use', id: 'tool_1', name: 'test_tool', input: { arg: 'value' } }],
      });

      mockCreate.mockResolvedValueOnce({
        stop_reason: 'end_turn',
        content: [{ type: 'text', text: 'Done' }],
      });

      const agent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
      await agent.chat('Test');

      // Verify second call includes tool results
      // Messages should be: [user, assistant (tool_use), user (tool_result)]
      const secondCall = mockCreate.mock.calls[1][0];
      expect(secondCall.messages.length).toBeGreaterThanOrEqual(3);

      // Find the tool result message
      const toolResultMessage = secondCall.messages.find(
        (m: MockMessage) => m.role === 'user' && Array.isArray(m.content) && m.content[0]?.type === 'tool_result'
      ) as MockMessage | undefined;
      expect(toolResultMessage).toBeDefined();
      expect((toolResultMessage?.content as Array<{ type: string; tool_use_id?: string }>)[0].tool_use_id).toBe('tool_1');
    });
  });
});

// =============================================================================
// Command Handler Tests
// =============================================================================

describe('Command Handlers', () => {
  let mockClient: MockAnthropicClient;
  let mockCreate: Mock;
  let mockAgent: CICDSecurityAgent;

  beforeEach(() => {
    vi.clearAllMocks();
    mockCreate = vi.fn().mockResolvedValue({
      stop_reason: 'end_turn',
      content: [{ type: 'text', text: 'Command executed successfully' }],
    });
    mockClient = {
      messages: {
        create: mockCreate,
      },
    };
    mockAgent = new CICDSecurityAgent(mockClient as unknown as Anthropic);
  });

  describe('handleScanCommand', () => {
    it('should scan path with severity', async () => {
      const result = await handleScanCommand('/app', 'HIGH,CRITICAL', mockAgent);
      expect(result).toBe('Command executed successfully');
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              role: 'user',
              content: expect.stringContaining('/app'),
            }),
          ]),
        })
      );
    });

    it('should include severity in query', async () => {
      await handleScanCommand('/test', 'LOW', mockAgent);
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              content: expect.stringContaining('LOW'),
            }),
          ]),
        })
      );
    });
  });

  describe('handleScanImageCommand', () => {
    it('should scan Docker image', async () => {
      const result = await handleScanImageCommand('nginx:latest', mockAgent);
      expect(result).toBe('Command executed successfully');
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              content: expect.stringContaining('nginx:latest'),
            }),
          ]),
        })
      );
    });
  });

  describe('handleStatusCommand', () => {
    it('should check platform status', async () => {
      const result = await handleStatusCommand(mockAgent);
      expect(result).toBe('Command executed successfully');
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              content: expect.stringContaining('health status'),
            }),
          ]),
        })
      );
    });
  });

  describe('handleReposCommand', () => {
    it('should list repositories', async () => {
      const result = await handleReposCommand(mockAgent);
      expect(result).toBe('Command executed successfully');
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              content: expect.stringContaining('repositories'),
            }),
          ]),
        })
      );
    });
  });

  describe('handleBuildsCommand', () => {
    it('should get builds for owner/repo', async () => {
      const result = await handleBuildsCommand('admin', 'my-repo', mockAgent);
      expect(result).toBe('Command executed successfully');
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              content: expect.stringContaining('admin/my-repo'),
            }),
          ]),
        })
      );
    });
  });

  describe('handleSecurityReportCommand', () => {
    it('should generate security report', async () => {
      const result = await handleSecurityReportCommand('/project', mockAgent);
      expect(result).toBe('Command executed successfully');
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              content: expect.stringContaining('/project'),
            }),
          ]),
        })
      );
    });

    it('should include Trivy, SonarQube, and Dependency-Track', async () => {
      await handleSecurityReportCommand('/test', mockAgent);
      const call = mockCreate.mock.calls[0][0];
      const message = call.messages[0].content;
      expect(message).toContain('Trivy');
      expect(message).toContain('SonarQube');
      expect(message).toContain('Dependency-Track');
    });
  });

  describe('handleMigrateCommand', () => {
    it('should migrate repository without token', async () => {
      const result = await handleMigrateCommand(
        'https://github.com/user/repo.git',
        'my-repo',
        false,
        mockAgent
      );
      expect(result).toBe('Command executed successfully');
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              content: expect.stringContaining('github.com/user/repo'),
            }),
          ]),
        })
      );
    });

    it('should include token info when token provided', async () => {
      await handleMigrateCommand('https://github.com/user/repo.git', 'my-repo', true, mockAgent);
      const call = mockCreate.mock.calls[0][0];
      const message = call.messages[0].content;
      expect(message).toContain('auth token');
    });

    it('should not include token info when no token', async () => {
      await handleMigrateCommand('https://github.com/user/repo.git', 'my-repo', false, mockAgent);
      const call = mockCreate.mock.calls[0][0];
      const message = call.messages[0].content;
      expect(message).not.toContain('auth token');
    });
  });

  describe('handleAskCommand', () => {
    it('should ask a question', async () => {
      const result = await handleAskCommand('What is the meaning of life?', mockAgent);
      expect(result).toBe('Command executed successfully');
      expect(mockCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: expect.arrayContaining([
            expect.objectContaining({
              content: 'What is the meaning of life?',
            }),
          ]),
        })
      );
    });
  });
});
