import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateSeverity, sanitizePath, sanitizeImageName, executeTool, config } from './tools.js';

// Mock child_process exec
vi.mock('node:child_process', () => ({
  exec: vi.fn((cmd, opts, callback) => {
    // Default mock implementation
    if (callback) {
      callback(null, { stdout: '{}', stderr: '' });
    }
    return { stdout: '{}', stderr: '' };
  }),
}));

vi.mock('node:util', async (importOriginal) => {
  const original = await importOriginal() as any;
  return {
    ...original,
    promisify: (fn: any) => {
      return async (...args: any[]) => {
        // Return mocked exec result
        const mockExecResult = (global as any).__mockExecResult;
        if (mockExecResult?.error) {
          throw mockExecResult.error;
        }
        return mockExecResult || { stdout: '{}', stderr: '' };
      };
    },
  };
});

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
    vi.resetAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  // ===========================================================================
  // SonarQube Handlers
  // ===========================================================================
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

  describe('sonar_get_issues', () => {
    it('should return issues for a project', async () => {
      const mockResponse = {
        issues: [
          { key: 'issue1', severity: 'MAJOR', type: 'BUG' },
          { key: 'issue2', severity: 'CRITICAL', type: 'VULNERABILITY' },
        ],
        total: 2,
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('sonar_get_issues', { projectKey: 'my-project' });
      const parsed = JSON.parse(result);

      expect(parsed.issues).toHaveLength(2);
      expect(parsed.total).toBe(2);
    });

    it('should include types filter in URL when provided', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ issues: [] }),
      });

      await executeTool('sonar_get_issues', { projectKey: 'my-project', types: 'BUG,VULNERABILITY' });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('types=BUG,VULNERABILITY'),
        expect.any(Object)
      );
    });
  });

  describe('sonar_get_security_hotspots', () => {
    it('should return security hotspots for a project', async () => {
      const mockResponse = {
        hotspots: [
          { key: 'hotspot1', message: 'Potential SQL injection' },
        ],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('sonar_get_security_hotspots', { projectKey: 'my-project' });
      const parsed = JSON.parse(result);

      expect(parsed.hotspots).toHaveLength(1);
    });
  });

  describe('sonar_get_metrics', () => {
    it('should return metrics for a project', async () => {
      const mockResponse = {
        component: {
          measures: [
            { metric: 'bugs', value: '5' },
            { metric: 'coverage', value: '80.5' },
          ],
        },
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('sonar_get_metrics', { projectKey: 'my-project' });
      const parsed = JSON.parse(result);

      expect(parsed.component.measures).toHaveLength(2);
    });
  });

  // ===========================================================================
  // Gitea Handlers
  // ===========================================================================
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

  describe('gitea_get_repo', () => {
    it('should return repository details', async () => {
      const mockResponse = {
        id: 1,
        name: 'my-repo',
        full_name: 'owner/my-repo',
        description: 'Test repo',
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('gitea_get_repo', { owner: 'owner', repo: 'my-repo' });
      const parsed = JSON.parse(result);

      expect(parsed.name).toBe('my-repo');
      expect(parsed.full_name).toBe('owner/my-repo');
    });
  });

  describe('gitea_get_branches', () => {
    it('should return branches for a repository', async () => {
      const mockResponse = [
        { name: 'main', commit: { id: 'abc123' } },
        { name: 'develop', commit: { id: 'def456' } },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('gitea_get_branches', { owner: 'owner', repo: 'repo' });
      const parsed = JSON.parse(result);

      expect(parsed).toHaveLength(2);
      expect(parsed[0].name).toBe('main');
    });
  });

  describe('gitea_get_commits', () => {
    it('should return commits with default limit', async () => {
      const mockResponse = [
        { sha: 'abc123', commit: { message: 'First commit' } },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      await executeTool('gitea_get_commits', { owner: 'owner', repo: 'repo' });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('limit=10'),
        expect.any(Object)
      );
    });

    it('should use custom limit when provided', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve([]),
      });

      await executeTool('gitea_get_commits', { owner: 'owner', repo: 'repo', limit: 25 });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('limit=25'),
        expect.any(Object)
      );
    });
  });

  describe('gitea_create_repo', () => {
    it('should create a new repository', async () => {
      const mockResponse = {
        id: 1,
        name: 'new-repo',
        full_name: 'user/new-repo',
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('gitea_create_repo', { name: 'new-repo' });
      const parsed = JSON.parse(result);

      expect(parsed.name).toBe('new-repo');
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should include description and private flag', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ id: 1 }),
      });

      await executeTool('gitea_create_repo', {
        name: 'new-repo',
        description: 'My description',
        private: true,
      });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"description":"My description"'),
        })
      );
    });
  });

  describe('gitea_migrate_repo', () => {
    it('should migrate a repository from GitHub', async () => {
      const mockResponse = { id: 1, name: 'migrated-repo' };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('gitea_migrate_repo', {
        cloneUrl: 'https://github.com/user/repo.git',
        repoName: 'migrated-repo',
      });
      const parsed = JSON.parse(result);

      expect(parsed.name).toBe('migrated-repo');
    });

    it('should include auth token when provided', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ id: 1 }),
      });

      await executeTool('gitea_migrate_repo', {
        cloneUrl: 'https://github.com/user/repo.git',
        repoName: 'migrated-repo',
        authToken: 'ghp_token123',
      });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('auth_token'),
        })
      );
    });
  });

  // ===========================================================================
  // Drone CI Handlers
  // ===========================================================================
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

  describe('drone_get_builds', () => {
    it('should return builds for a repository', async () => {
      const mockResponse = [
        { number: 1, status: 'success' },
        { number: 2, status: 'failure' },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('drone_get_builds', { owner: 'owner', repo: 'repo' });
      const parsed = JSON.parse(result);

      expect(parsed).toHaveLength(2);
      expect(parsed[0].number).toBe(1);
    });
  });

  describe('drone_get_build', () => {
    it('should return a specific build', async () => {
      const mockResponse = {
        number: 5,
        status: 'success',
        stages: [{ name: 'build', status: 'success' }],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('drone_get_build', { owner: 'owner', repo: 'repo', build: 5 });
      const parsed = JSON.parse(result);

      expect(parsed.number).toBe(5);
      expect(parsed.status).toBe('success');
    });
  });

  describe('drone_get_build_logs', () => {
    it('should return build logs with default stage and step', async () => {
      const mockResponse = [
        { out: 'Building...' },
        { out: 'Done!' },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      await executeTool('drone_get_build_logs', { owner: 'owner', repo: 'repo', build: 1 });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/logs/1/1'),
        expect.any(Object)
      );
    });

    it('should use custom stage and step when provided', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve([]),
      });

      await executeTool('drone_get_build_logs', { owner: 'owner', repo: 'repo', build: 1, stage: 2, step: 3 });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/logs/2/3'),
        expect.any(Object)
      );
    });
  });

  describe('drone_trigger_build', () => {
    it('should return error when drone token is not set', async () => {
      const originalToken = config.drone.token;
      config.drone.token = '';

      const result = await executeTool('drone_trigger_build', { owner: 'owner', repo: 'repo' });
      const parsed = JSON.parse(result);

      expect(parsed.error).toContain('Drone token required');

      config.drone.token = originalToken;
    });

    it('should trigger a build with token', async () => {
      const originalToken = config.drone.token;
      config.drone.token = 'test-token';

      const mockResponse = { number: 10, status: 'pending' };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('drone_trigger_build', { owner: 'owner', repo: 'repo' });
      const parsed = JSON.parse(result);

      expect(parsed.number).toBe(10);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('branch=main'),
        expect.objectContaining({ method: 'POST' })
      );

      config.drone.token = originalToken;
    });

    it('should use custom branch when provided', async () => {
      const originalToken = config.drone.token;
      config.drone.token = 'test-token';

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ number: 10 }),
      });

      await executeTool('drone_trigger_build', { owner: 'owner', repo: 'repo', branch: 'develop' });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('branch=develop'),
        expect.any(Object)
      );

      config.drone.token = originalToken;
    });
  });

  // ===========================================================================
  // Registry Handlers
  // ===========================================================================
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

  describe('registry_get_tags', () => {
    it('should return tags for an image', async () => {
      const mockResponse = {
        name: 'my-image',
        tags: ['latest', 'v1.0', 'v2.0'],
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('registry_get_tags', { image: 'my-image' });
      const parsed = JSON.parse(result);

      expect(parsed.tags).toHaveLength(3);
      expect(parsed.name).toBe('my-image');
    });
  });

  // ===========================================================================
  // Dependency-Track Handlers
  // ===========================================================================
  describe('dtrack_list_projects', () => {
    it('should return error when API key is not set', async () => {
      const originalKey = config.dependencyTrack.apiKey;
      config.dependencyTrack.apiKey = '';

      const result = await executeTool('dtrack_list_projects', {});
      const parsed = JSON.parse(result);

      expect(parsed.error).toContain('API key not configured');

      config.dependencyTrack.apiKey = originalKey;
    });

    it('should return projects when API key is set', async () => {
      const originalKey = config.dependencyTrack.apiKey;
      config.dependencyTrack.apiKey = 'test-api-key';

      const mockResponse = [
        { uuid: 'uuid1', name: 'Project 1' },
        { uuid: 'uuid2', name: 'Project 2' },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('dtrack_list_projects', {});
      const parsed = JSON.parse(result);

      expect(parsed).toHaveLength(2);
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({ 'X-Api-Key': 'test-api-key' }),
        })
      );

      config.dependencyTrack.apiKey = originalKey;
    });
  });

  describe('dtrack_get_vulnerabilities', () => {
    it('should return vulnerabilities for a project', async () => {
      const originalKey = config.dependencyTrack.apiKey;
      config.dependencyTrack.apiKey = 'test-api-key';

      const mockResponse = [
        { vulnId: 'CVE-2021-1234', severity: 'HIGH' },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('dtrack_get_vulnerabilities', { projectUuid: 'uuid1' });
      const parsed = JSON.parse(result);

      expect(parsed).toHaveLength(1);
      expect(parsed[0].vulnId).toBe('CVE-2021-1234');

      config.dependencyTrack.apiKey = originalKey;
    });
  });

  describe('dtrack_get_findings', () => {
    it('should return findings for a project', async () => {
      const originalKey = config.dependencyTrack.apiKey;
      config.dependencyTrack.apiKey = 'test-api-key';

      const mockResponse = [
        { component: { name: 'lodash' }, vulnerability: { vulnId: 'CVE-2021-5678' } },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('dtrack_get_findings', { projectUuid: 'uuid1' });
      const parsed = JSON.parse(result);

      expect(parsed).toHaveLength(1);

      config.dependencyTrack.apiKey = originalKey;
    });
  });

  describe('dtrack_get_components', () => {
    it('should return components for a project', async () => {
      const originalKey = config.dependencyTrack.apiKey;
      config.dependencyTrack.apiKey = 'test-api-key';

      const mockResponse = [
        { name: 'express', version: '4.18.2' },
        { name: 'lodash', version: '4.17.21' },
      ];

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await executeTool('dtrack_get_components', { projectUuid: 'uuid1' });
      const parsed = JSON.parse(result);

      expect(parsed).toHaveLength(2);

      config.dependencyTrack.apiKey = originalKey;
    });
  });

  // ===========================================================================
  // Platform Status Handler
  // ===========================================================================
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
      expect(parsed.services.dependencyTrack).toBeDefined();
      expect(parsed.services.registry).toBeDefined();
    });

    it('should mark healthy services correctly', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
      });

      const result = await executeTool('check_platform_status', {});
      const parsed = JSON.parse(result);

      expect(parsed.services.gitea.status).toBe('healthy');
      expect(parsed.services.gitea.statusCode).toBe(200);
    });

    it('should mark degraded services correctly', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
      });

      const result = await executeTool('check_platform_status', {});
      const parsed = JSON.parse(result);

      expect(parsed.services.gitea.status).toBe('unhealthy');
      expect(parsed.services.gitea.statusCode).toBe(503);
    });

    it('should handle service failures gracefully', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Connection refused'));

      const result = await executeTool('check_platform_status', {});
      const parsed = JSON.parse(result);

      expect(parsed.services.gitea.status).toBe('unreachable');
      expect(parsed.services.gitea.error).toContain('Connection refused');
    });
  });

  // ===========================================================================
  // Trivy Handlers
  // ===========================================================================
  describe('trivy_scan_path', () => {
    beforeEach(() => {
      (global as any).__mockExecResult = { stdout: '{"Results":[]}', stderr: '' };
    });

    afterEach(() => {
      delete (global as any).__mockExecResult;
    });

    it('should return error for invalid path', async () => {
      const result = await executeTool('trivy_scan_path', { path: '' });
      const parsed = JSON.parse(result);

      expect(parsed.error).toContain('Invalid path');
    });

    it('should return error for short path', async () => {
      const result = await executeTool('trivy_scan_path', { path: 'x' });
      const parsed = JSON.parse(result);

      expect(parsed.error).toContain('Invalid path');
    });

    it('should scan a valid path successfully', async () => {
      (global as any).__mockExecResult = {
        stdout: JSON.stringify({ Results: [{ Target: '/app', Vulnerabilities: [] }] }),
        stderr: '',
      };

      const result = await executeTool('trivy_scan_path', { path: '/home/user/project' });
      const parsed = JSON.parse(result);

      expect(parsed.Results).toBeDefined();
    });

    it('should handle exec errors with stdout', async () => {
      const error: any = new Error('Command failed');
      error.stdout = JSON.stringify({ Results: [], error: 'scan failed' });
      (global as any).__mockExecResult = { error };

      const result = await executeTool('trivy_scan_path', { path: '/home/user/project' });
      const parsed = JSON.parse(result);

      expect(parsed.Results).toBeDefined();
    });

    it('should handle exec errors with non-JSON stdout', async () => {
      const error: any = new Error('Command failed');
      error.stdout = 'Non-JSON output';
      (global as any).__mockExecResult = { error };

      const result = await executeTool('trivy_scan_path', { path: '/home/user/project' });
      const parsed = JSON.parse(result);

      expect(parsed.output).toBe('Non-JSON output');
    });

    it('should handle exec errors without stdout', async () => {
      const error = new Error('Command not found');
      (global as any).__mockExecResult = { error };

      const result = await executeTool('trivy_scan_path', { path: '/home/user/project' });
      const parsed = JSON.parse(result);

      expect(parsed.error).toContain('Command not found');
    });

    it('should use custom severity levels', async () => {
      (global as any).__mockExecResult = {
        stdout: JSON.stringify({ Results: [] }),
        stderr: '',
      };

      const result = await executeTool('trivy_scan_path', {
        path: '/home/user/project',
        severity: 'LOW,MEDIUM'
      });
      const parsed = JSON.parse(result);

      expect(parsed.Results).toBeDefined();
    });
  });

  describe('trivy_scan_image', () => {
    beforeEach(() => {
      (global as any).__mockExecResult = { stdout: '{"Results":[]}', stderr: '' };
    });

    afterEach(() => {
      delete (global as any).__mockExecResult;
    });

    it('should return error for invalid image name', async () => {
      const result = await executeTool('trivy_scan_image', { image: '' });
      const parsed = JSON.parse(result);

      expect(parsed.error).toContain('Invalid image');
    });

    it('should return error for short image name', async () => {
      const result = await executeTool('trivy_scan_image', { image: 'x' });
      const parsed = JSON.parse(result);

      expect(parsed.error).toContain('Invalid image');
    });

    it('should scan a valid image successfully', async () => {
      (global as any).__mockExecResult = {
        stdout: JSON.stringify({ Results: [{ Target: 'nginx:latest', Vulnerabilities: [] }] }),
        stderr: '',
      };

      const result = await executeTool('trivy_scan_image', { image: 'nginx:latest' });
      const parsed = JSON.parse(result);

      expect(parsed.Results).toBeDefined();
    });

    it('should handle exec errors with stdout', async () => {
      const error: any = new Error('Command failed');
      error.stdout = JSON.stringify({ Results: [], error: 'scan failed' });
      (global as any).__mockExecResult = { error };

      const result = await executeTool('trivy_scan_image', { image: 'nginx:latest' });
      const parsed = JSON.parse(result);

      expect(parsed.Results).toBeDefined();
    });

    it('should handle exec errors with non-JSON stdout', async () => {
      const error: any = new Error('Command failed');
      error.stdout = 'Non-JSON output';
      (global as any).__mockExecResult = { error };

      const result = await executeTool('trivy_scan_image', { image: 'nginx:latest' });
      const parsed = JSON.parse(result);

      expect(parsed.output).toBe('Non-JSON output');
    });

    it('should handle exec errors without stdout', async () => {
      const error = new Error('Docker not found');
      (global as any).__mockExecResult = { error };

      const result = await executeTool('trivy_scan_image', { image: 'nginx:latest' });
      const parsed = JSON.parse(result);

      expect(parsed.error).toContain('Docker not found');
    });

    it('should use custom severity levels', async () => {
      (global as any).__mockExecResult = {
        stdout: JSON.stringify({ Results: [] }),
        stderr: '',
      };

      const result = await executeTool('trivy_scan_image', {
        image: 'nginx:latest',
        severity: 'CRITICAL'
      });
      const parsed = JSON.parse(result);

      expect(parsed.Results).toBeDefined();
    });
  });

  // ===========================================================================
  // Network Timeout and Error Handling
  // ===========================================================================
  describe('Error Handling', () => {
    it('should handle network timeouts', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('timeout'));

      const result = await executeTool('sonar_list_projects', {});
      const parsed = JSON.parse(result);

      expect(parsed.error).toBeDefined();
    });

    it('should handle JSON parse errors', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.reject(new Error('Invalid JSON')),
      });

      const result = await executeTool('sonar_list_projects', {});
      const parsed = JSON.parse(result);

      expect(parsed.error).toBeDefined();
    });
  });
});
