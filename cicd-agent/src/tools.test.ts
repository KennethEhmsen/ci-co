import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateSeverity, sanitizePath, sanitizeImageName, executeTool } from './tools.js';

// =============================================================================
// Utility Function Tests
// =============================================================================

describe('validateSeverity', () => {
  it('should return valid severity levels unchanged', () => {
    expect(validateSeverity('HIGH,CRITICAL')).toBe('HIGH,CRITICAL');
  });

  it('should handle single valid severity', () => {
    expect(validateSeverity('HIGH')).toBe('HIGH');
  });

  it('should handle all valid severity levels', () => {
    expect(validateSeverity('UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL')).toBe('UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL');
  });

  it('should filter out invalid severity levels', () => {
    expect(validateSeverity('HIGH,INVALID,CRITICAL')).toBe('HIGH,CRITICAL');
  });

  it('should return default for completely invalid input', () => {
    expect(validateSeverity('INVALID,FAKE')).toBe('HIGH,CRITICAL');
  });

  it('should return default for empty string', () => {
    expect(validateSeverity('')).toBe('HIGH,CRITICAL');
  });

  it('should handle lowercase input by converting to uppercase', () => {
    expect(validateSeverity('high,critical')).toBe('HIGH,CRITICAL');
  });

  it('should handle mixed case input', () => {
    expect(validateSeverity('High,CRITICAL,low')).toBe('HIGH,CRITICAL,LOW');
  });

  it('should trim whitespace around levels', () => {
    expect(validateSeverity(' HIGH , CRITICAL ')).toBe('HIGH,CRITICAL');
  });

  it('should handle extra commas gracefully', () => {
    expect(validateSeverity('HIGH,,CRITICAL')).toBe('HIGH,CRITICAL');
  });
});

describe('sanitizePath', () => {
  it('should allow valid Unix paths', () => {
    expect(sanitizePath('/home/user/project')).toBe('/home/user/project');
  });

  it('should allow valid Windows paths', () => {
    expect(sanitizePath('C:\\Users\\project')).toBe('C:\\Users\\project');
  });

  it('should allow paths with spaces', () => {
    expect(sanitizePath('/home/user/my project')).toBe('/home/user/my project');
  });

  it('should allow paths with dots', () => {
    expect(sanitizePath('/home/user/file.txt')).toBe('/home/user/file.txt');
  });

  it('should allow paths with hyphens and underscores', () => {
    expect(sanitizePath('/home/my-project_v1')).toBe('/home/my-project_v1');
  });

  it('should remove shell metacharacters', () => {
    expect(sanitizePath('/home/user; rm -rf /')).toBe('/home/user rm -rf /');
  });

  it('should remove backticks', () => {
    expect(sanitizePath('/home/`whoami`')).toBe('/home/whoami');
  });

  it('should remove dollar signs', () => {
    expect(sanitizePath('/home/$USER')).toBe('/home/USER');
  });

  it('should remove pipe characters', () => {
    expect(sanitizePath('/home/user | cat /etc/passwd')).toBe('/home/user  cat /etc/passwd');
  });

  it('should prevent path traversal with ../', () => {
    expect(sanitizePath('/home/user/../../../etc/passwd')).toBe('/home/user/etc/passwd');
  });

  it('should prevent Windows path traversal with ..\\', () => {
    expect(sanitizePath('C:\\Users\\..\\..\\Windows')).toBe('C:\\Users\\Windows');
  });

  it('should handle multiple path traversal attempts', () => {
    expect(sanitizePath('../../../../etc/passwd')).toBe('etc/passwd');
  });

  it('should handle empty string', () => {
    expect(sanitizePath('')).toBe('');
  });
});

describe('sanitizeImageName', () => {
  it('should allow simple image names', () => {
    expect(sanitizeImageName('nginx')).toBe('nginx');
  });

  it('should allow image names with tags', () => {
    expect(sanitizeImageName('nginx:latest')).toBe('nginx:latest');
  });

  it('should allow image names with version tags', () => {
    expect(sanitizeImageName('node:20-alpine')).toBe('node:20-alpine');
  });

  it('should allow registry prefixes', () => {
    expect(sanitizeImageName('docker.io/library/nginx')).toBe('docker.io/library/nginx');
  });

  it('should allow localhost registry', () => {
    expect(sanitizeImageName('localhost:5000/myapp:v1')).toBe('localhost:5000/myapp:v1');
  });

  it('should allow digest references', () => {
    expect(sanitizeImageName('nginx@sha256:abc123')).toBe('nginx@sha256:abc123');
  });

  it('should remove shell metacharacters', () => {
    // Semicolons and spaces are removed, only keeping allowed chars
    expect(sanitizeImageName('nginx; rm -rf /')).toBe('nginxrm-rf/');
  });

  it('should remove backticks', () => {
    expect(sanitizeImageName('`whoami`/nginx')).toBe('whoami/nginx');
  });

  it('should remove dollar signs', () => {
    expect(sanitizeImageName('$IMAGE_NAME')).toBe('IMAGE_NAME');
  });

  it('should handle empty string', () => {
    expect(sanitizeImageName('')).toBe('');
  });

  it('should allow underscores in image names', () => {
    expect(sanitizeImageName('my_image_name')).toBe('my_image_name');
  });
});

// =============================================================================
// executeTool Tests
// =============================================================================

describe('executeTool', () => {
  it('should return error for unknown tool', async () => {
    const result = await executeTool('unknown_tool', {});
    const parsed = JSON.parse(result);
    expect(parsed.error).toBe('Unknown tool: unknown_tool');
  });

  it('should return valid JSON for all responses', async () => {
    const result = await executeTool('unknown_tool', {});
    expect(() => JSON.parse(result)).not.toThrow();
  });
});

// =============================================================================
// Handler Tests with Mocked Dependencies
// =============================================================================

describe('Tool Handlers', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    // Reset fetch mock before each test
    vi.resetAllMocks();
  });

  afterEach(() => {
    // Restore original fetch
    global.fetch = originalFetch;
  });

  describe('sonar_list_projects', () => {
    it('should return projects from SonarQube API', async () => {
      const mockResponse = {
        components: [
          { key: 'project1', name: 'Project 1' },
          { key: 'project2', name: 'Project 2' },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('sonar_list_projects', {});
      const parsed = JSON.parse(result);

      expect(parsed.components).toHaveLength(2);
      expect(parsed.components[0].key).toBe('project1');
    });

    it('should handle API errors gracefully', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const result = await executeTool('sonar_list_projects', {});
      const parsed = JSON.parse(result);

      expect(parsed.error).toContain('500');
    });
  });

  describe('gitea_list_repos', () => {
    it('should return repositories from Gitea API', async () => {
      const mockResponse = [
        { id: 1, name: 'repo1', full_name: 'user/repo1' },
        { id: 2, name: 'repo2', full_name: 'user/repo2' },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('gitea_list_repos', {});
      const parsed = JSON.parse(result);

      expect(parsed).toHaveLength(2);
      expect(parsed[0].name).toBe('repo1');
    });
  });

  describe('drone_list_repos', () => {
    it('should return repositories from Drone API', async () => {
      const mockResponse = [
        { id: 1, slug: 'user/repo1', active: true },
        { id: 2, slug: 'user/repo2', active: false },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('drone_list_repos', {});
      const parsed = JSON.parse(result);

      expect(parsed).toHaveLength(2);
      expect(parsed[0].slug).toBe('user/repo1');
    });
  });

  describe('registry_list_images', () => {
    it('should return catalog from registry API', async () => {
      const mockResponse = {
        repositories: ['image1', 'image2', 'image3'],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('registry_list_images', {});
      const parsed = JSON.parse(result);

      expect(parsed.repositories).toHaveLength(3);
    });
  });

  describe('check_platform_status', () => {
    it('should check all platform services', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
      });

      const result = await executeTool('check_platform_status', {});
      const parsed = JSON.parse(result);

      expect(parsed.timestamp).toBeDefined();
      expect(parsed.services).toBeDefined();
      expect(parsed.services.gitea).toBeDefined();
      expect(parsed.services.drone).toBeDefined();
      expect(parsed.services.sonarqube).toBeDefined();
    });

    it('should handle service failures gracefully', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Connection refused'));

      const result = await executeTool('check_platform_status', {});
      const parsed = JSON.parse(result);

      expect(parsed.services.gitea.status).toBe('unreachable');
      expect(parsed.services.gitea.error).toContain('Connection refused');
    });
  });
});
