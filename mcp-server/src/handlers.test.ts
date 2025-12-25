import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import {
  validateSeverity,
  sanitizePath,
  sanitizeImageName,
  basicAuth,
  fetchJson,
  config,
  trivyScanPath,
  trivyScanImage,
  sonarGetProjects,
  sonarGetIssues,
  sonarGetSecurityHotspots,
  sonarGetMetrics,
  dtrackGetProjects,
  dtrackGetVulnerabilities,
  dtrackGetFindings,
  dtrackGetComponents,
  giteaGetRepos,
  giteaGetRepo,
  giteaGetBranches,
  giteaGetCommits,
  giteaCreateRepo,
  giteaMigrateRepo,
  droneGetRepos,
  droneGetBuilds,
  droneGetBuild,
  droneGetBuildLogs,
  droneTriggerBuild,
  registryGetCatalog,
  registryGetTags,
  securityScanAll,
  checkPlatformStatus,
} from './handlers.js';

/** Mock exec result interface */
interface MockExecResult {
  stdout: string;
  stderr: string;
  error?: {
    message: string;
    stdout?: string;
  };
}

/** Extended global for mocks */
interface MockGlobal {
  __mockExecResult: MockExecResult | null;
}

// Mock node:child_process for exec tests
vi.mock('node:child_process', () => ({
  exec: vi.fn((cmd: string, opts: unknown, callback?: (err: Error | null, result: { stdout: string; stderr: string }) => void) => {
    if (callback) {
      callback(null, { stdout: '{}', stderr: '' });
    }
    return { stdout: '{}', stderr: '' };
  }),
}));

vi.mock('node:util', async (importOriginal) => {
  const original = await importOriginal() as Record<string, unknown>;
  return {
    ...original,
    promisify: (_fn: unknown) => {
      return async (..._args: unknown[]) => {
        const mockExecResult = (global as unknown as MockGlobal).__mockExecResult;
        if (mockExecResult?.error) {
          const error = new Error(mockExecResult.error.message) as Error & { stdout?: string };
          error.stdout = mockExecResult.error.stdout;
          throw error;
        }
        return mockExecResult || { stdout: '{}', stderr: '' };
      };
    },
  };
});

// =============================================================================
// Test Setup
// =============================================================================
describe('Handlers', () => {
  const originalFetch = global.fetch;
  let mockFetch: Mock;

  beforeEach(() => {
    mockFetch = vi.fn();
    global.fetch = mockFetch as unknown as typeof fetch;
    (global as unknown as MockGlobal).__mockExecResult = null;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.clearAllMocks();
  });

  // ===========================================================================
  // Utility Function Tests
  // ===========================================================================
  describe('validateSeverity', () => {
    it('returns valid severity levels unchanged', () => {
      expect(validateSeverity('HIGH,CRITICAL')).toBe('HIGH,CRITICAL');
    });

    it('filters out invalid levels', () => {
      expect(validateSeverity('HIGH,INVALID,CRITICAL')).toBe('HIGH,CRITICAL');
    });

    it('handles lowercase input', () => {
      expect(validateSeverity('high,critical')).toBe('HIGH,CRITICAL');
    });

    it('returns default for empty string', () => {
      expect(validateSeverity('')).toBe('HIGH,CRITICAL');
    });

    it('returns default for all invalid levels', () => {
      expect(validateSeverity('INVALID,FAKE')).toBe('HIGH,CRITICAL');
    });

    it('handles single valid level', () => {
      expect(validateSeverity('MEDIUM')).toBe('MEDIUM');
    });

    it('handles all valid levels', () => {
      expect(validateSeverity('UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL')).toBe('UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL');
    });

    it('handles whitespace in input', () => {
      expect(validateSeverity(' HIGH , CRITICAL ')).toBe('HIGH,CRITICAL');
    });
  });

  describe('sanitizePath', () => {
    it('allows normal paths', () => {
      expect(sanitizePath('/home/user/project')).toBe('/home/user/project');
    });

    it('allows Windows paths', () => {
      expect(sanitizePath('C:\\Users\\test')).toBe('C:\\Users\\test');
    });

    it('removes shell metacharacters', () => {
      expect(sanitizePath('/path/$(whoami)')).toBe('/path/whoami');
      expect(sanitizePath('/path/`id`')).toBe('/path/id');
    });

    it('removes path traversal attempts', () => {
      expect(sanitizePath('/path/../../../etc/passwd')).toBe('/path/etc/passwd');
    });

    it('allows spaces in paths', () => {
      expect(sanitizePath('/path/to my/project')).toBe('/path/to my/project');
    });

    it('allows dots in filenames', () => {
      expect(sanitizePath('/path/file.txt')).toBe('/path/file.txt');
    });

    it('removes semicolons', () => {
      expect(sanitizePath('/path; rm -rf /')).toBe('/path rm -rf /');
    });

    it('removes pipe characters', () => {
      expect(sanitizePath('/path | cat /etc/passwd')).toBe('/path  cat /etc/passwd');
    });
  });

  describe('sanitizeImageName', () => {
    it('allows simple image names', () => {
      expect(sanitizeImageName('nginx')).toBe('nginx');
    });

    it('allows image:tag format', () => {
      expect(sanitizeImageName('nginx:latest')).toBe('nginx:latest');
    });

    it('allows registry/image format', () => {
      expect(sanitizeImageName('localhost:5000/myapp')).toBe('localhost:5000/myapp');
    });

    it('allows digest format', () => {
      expect(sanitizeImageName('nginx@sha256:abc123')).toBe('nginx@sha256:abc123');
    });

    it('removes shell metacharacters', () => {
      // sanitizeImageName removes spaces and semicolons
      expect(sanitizeImageName('nginx; rm -rf /')).toBe('nginxrm-rf/');
    });

    it('allows underscores and hyphens', () => {
      expect(sanitizeImageName('my-app_v1:latest')).toBe('my-app_v1:latest');
    });
  });

  describe('basicAuth', () => {
    it('encodes credentials correctly', () => {
      const result = basicAuth('user', 'pass');
      expect(result).toBe('Basic dXNlcjpwYXNz');
    });

    it('handles special characters', () => {
      const result = basicAuth('user@domain.com', 'p@ss:word!');
      expect(result).toMatch(/^Basic /);
    });
  });

  describe('config', () => {
    it('has all required service configurations', () => {
      expect(config).toHaveProperty('gitea');
      expect(config).toHaveProperty('drone');
      expect(config).toHaveProperty('sonarqube');
      expect(config).toHaveProperty('dependencyTrack');
      expect(config).toHaveProperty('trivy');
      expect(config).toHaveProperty('registry');
    });

    it('gitea has required properties', () => {
      expect(config.gitea).toHaveProperty('url');
      expect(config.gitea).toHaveProperty('user');
      expect(config.gitea).toHaveProperty('password');
    });
  });

  // ===========================================================================
  // fetchJson Tests
  // ===========================================================================
  describe('fetchJson', () => {
    it('returns JSON for successful response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: 'test' }),
      });

      const result = await fetchJson('http://example.com/api');
      expect(result).toEqual({ data: 'test' });
    });

    it('throws error for non-ok response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(fetchJson('http://example.com/api')).rejects.toThrow('HTTP 404: Not Found');
    });

    it('passes headers correctly', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });

      await fetchJson('http://example.com/api', {
        headers: { Authorization: 'Bearer token' },
      });

      expect(mockFetch).toHaveBeenCalledWith('http://example.com/api', expect.objectContaining({
        headers: { Authorization: 'Bearer token' },
      }));
    });
  });

  // ===========================================================================
  // SonarQube Handler Tests
  // ===========================================================================
  describe('SonarQube handlers', () => {
    describe('sonarGetProjects', () => {
      it('fetches projects successfully', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ components: [{ key: 'project1' }] }),
        });

        const result = await sonarGetProjects();
        expect(result).toEqual({ components: [{ key: 'project1' }] });
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/api/projects/search'),
          expect.objectContaining({
            headers: expect.objectContaining({
              Authorization: expect.stringMatching(/^Basic /),
            }),
          })
        );
      });
    });

    describe('sonarGetIssues', () => {
      it('fetches issues without type filter', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ issues: [] }),
        });

        await sonarGetIssues('my-project');
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('componentKeys=my-project'),
          expect.anything()
        );
      });

      it('fetches issues with type filter', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ issues: [] }),
        });

        await sonarGetIssues('my-project', 'BUG');
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('types=BUG'),
          expect.anything()
        );
      });
    });

    describe('sonarGetSecurityHotspots', () => {
      it('fetches hotspots for project', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ hotspots: [] }),
        });

        const result = await sonarGetSecurityHotspots('my-project');
        expect(result).toEqual({ hotspots: [] });
      });
    });

    describe('sonarGetMetrics', () => {
      it('fetches metrics for project', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ component: { measures: [] } }),
        });

        const result = await sonarGetMetrics('my-project');
        expect(result).toEqual({ component: { measures: [] } });
      });
    });
  });

  // ===========================================================================
  // Dependency-Track Handler Tests
  // ===========================================================================
  describe('Dependency-Track handlers', () => {
    const originalApiKey = config.dependencyTrack.apiKey;

    beforeEach(() => {
      config.dependencyTrack.apiKey = 'test-api-key';
    });

    afterEach(() => {
      config.dependencyTrack.apiKey = originalApiKey;
    });

    describe('dtrackGetProjects', () => {
      it('throws error when API key not configured', async () => {
        config.dependencyTrack.apiKey = '';
        await expect(dtrackGetProjects()).rejects.toThrow('Dependency-Track API key not configured');
      });

      it('fetches projects successfully', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ uuid: 'proj-1' }]),
        });

        const result = await dtrackGetProjects();
        expect(result).toEqual([{ uuid: 'proj-1' }]);
      });
    });

    describe('dtrackGetVulnerabilities', () => {
      it('throws error when API key not configured', async () => {
        config.dependencyTrack.apiKey = '';
        await expect(dtrackGetVulnerabilities('uuid')).rejects.toThrow('Dependency-Track API key not configured');
      });

      it('fetches vulnerabilities successfully', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ vulnId: 'CVE-2021-1234' }]),
        });

        const result = await dtrackGetVulnerabilities('proj-uuid');
        expect(result).toEqual([{ vulnId: 'CVE-2021-1234' }]);
      });
    });

    describe('dtrackGetFindings', () => {
      it('throws error when API key not configured', async () => {
        config.dependencyTrack.apiKey = '';
        await expect(dtrackGetFindings('uuid')).rejects.toThrow('Dependency-Track API key not configured');
      });

      it('fetches findings successfully', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ finding: 'test' }]),
        });

        const result = await dtrackGetFindings('proj-uuid');
        expect(result).toEqual([{ finding: 'test' }]);
      });
    });

    describe('dtrackGetComponents', () => {
      it('throws error when API key not configured', async () => {
        config.dependencyTrack.apiKey = '';
        await expect(dtrackGetComponents('uuid')).rejects.toThrow('Dependency-Track API key not configured');
      });

      it('fetches components successfully', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ name: 'lodash' }]),
        });

        const result = await dtrackGetComponents('proj-uuid');
        expect(result).toEqual([{ name: 'lodash' }]);
      });
    });
  });

  // ===========================================================================
  // Gitea Handler Tests
  // ===========================================================================
  describe('Gitea handlers', () => {
    describe('giteaGetRepos', () => {
      it('fetches repos successfully', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ name: 'repo1' }]),
        });

        const result = await giteaGetRepos();
        expect(result).toEqual([{ name: 'repo1' }]);
      });
    });

    describe('giteaGetRepo', () => {
      it('fetches single repo', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ name: 'myrepo', owner: { login: 'user' } }),
        });

        const result = await giteaGetRepo('user', 'myrepo');
        expect(result).toEqual({ name: 'myrepo', owner: { login: 'user' } });
      });
    });

    describe('giteaGetBranches', () => {
      it('fetches branches for repo', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ name: 'main' }, { name: 'develop' }]),
        });

        const result = await giteaGetBranches('user', 'repo');
        expect(result).toHaveLength(2);
      });
    });

    describe('giteaGetCommits', () => {
      it('fetches commits with default limit', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ sha: 'abc123' }]),
        });

        await giteaGetCommits('user', 'repo');
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('limit=10'),
          expect.anything()
        );
      });

      it('fetches commits with custom limit', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([]),
        });

        await giteaGetCommits('user', 'repo', 50);
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('limit=50'),
          expect.anything()
        );
      });
    });

    describe('giteaCreateRepo', () => {
      it('creates repo with defaults', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ id: 1, name: 'newrepo' }),
        });

        const result = await giteaCreateRepo('newrepo');
        expect(result).toEqual({ id: 1, name: 'newrepo' });
        expect(mockFetch).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({
            method: 'POST',
            body: expect.stringContaining('"name":"newrepo"'),
          })
        );
      });

      it('creates private repo with description', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ id: 2 }),
        });

        await giteaCreateRepo('private-repo', 'A private repository', true);
        expect(mockFetch).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({
            body: expect.stringContaining('"private":true'),
          })
        );
      });
    });

    describe('giteaMigrateRepo', () => {
      it('migrates repo without auth token', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ id: 1 }),
        });

        await giteaMigrateRepo('https://github.com/user/repo.git', 'my-repo');
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/repos/migrate'),
          expect.objectContaining({
            method: 'POST',
          })
        );
      });

      it('migrates repo with auth token', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ id: 1 }),
        });

        await giteaMigrateRepo('https://github.com/user/repo.git', 'my-repo', 'ghp_token');
        expect(mockFetch).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({
            body: expect.stringContaining('auth_token'),
          })
        );
      });
    });
  });

  // ===========================================================================
  // Drone Handler Tests
  // ===========================================================================
  describe('Drone handlers', () => {
    const originalToken = config.drone.token;

    afterEach(() => {
      config.drone.token = originalToken;
    });

    describe('droneGetRepos', () => {
      it('fetches repos without token', async () => {
        config.drone.token = '';
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([]),
        });

        await droneGetRepos();
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/api/user/repos'),
          expect.not.objectContaining({
            headers: expect.objectContaining({
              Authorization: expect.anything(),
            }),
          })
        );
      });

      it('fetches repos with token', async () => {
        config.drone.token = 'test-token';
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ name: 'repo' }]),
        });

        await droneGetRepos();
        expect(mockFetch).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({
            headers: { Authorization: 'Bearer test-token' },
          })
        );
      });
    });

    describe('droneGetBuilds', () => {
      it('fetches builds for repo', async () => {
        config.drone.token = 'test-token';
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ number: 1 }]),
        });

        const result = await droneGetBuilds('owner', 'repo');
        expect(result).toEqual([{ number: 1 }]);
      });
    });

    describe('droneGetBuild', () => {
      it('fetches specific build', async () => {
        config.drone.token = 'test-token';
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ number: 42, status: 'success' }),
        });

        const result = await droneGetBuild('owner', 'repo', 42);
        expect(result).toEqual({ number: 42, status: 'success' });
      });
    });

    describe('droneGetBuildLogs', () => {
      it('fetches logs with default stage/step', async () => {
        config.drone.token = 'test-token';
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([{ out: 'log line' }]),
        });

        await droneGetBuildLogs('owner', 'repo', 1);
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/logs/1/1'),
          expect.anything()
        );
      });

      it('fetches logs with custom stage/step', async () => {
        config.drone.token = 'test-token';
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([]),
        });

        await droneGetBuildLogs('owner', 'repo', 1, 2, 3);
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('/logs/2/3'),
          expect.anything()
        );
      });
    });

    describe('droneTriggerBuild', () => {
      it('throws error when token not configured', async () => {
        config.drone.token = '';
        await expect(droneTriggerBuild('owner', 'repo')).rejects.toThrow('Drone token required');
      });

      it('triggers build with default branch', async () => {
        config.drone.token = 'test-token';
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ number: 43 }),
        });

        await droneTriggerBuild('owner', 'repo');
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('branch=main'),
          expect.objectContaining({ method: 'POST' })
        );
      });

      it('triggers build with custom branch', async () => {
        config.drone.token = 'test-token';
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ number: 44 }),
        });

        await droneTriggerBuild('owner', 'repo', 'develop');
        expect(mockFetch).toHaveBeenCalledWith(
          expect.stringContaining('branch=develop'),
          expect.anything()
        );
      });
    });
  });

  // ===========================================================================
  // Registry Handler Tests
  // ===========================================================================
  describe('Registry handlers', () => {
    describe('registryGetCatalog', () => {
      it('fetches catalog', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ repositories: ['image1', 'image2'] }),
        });

        const result = await registryGetCatalog();
        expect(result).toEqual({ repositories: ['image1', 'image2'] });
      });
    });

    describe('registryGetTags', () => {
      it('fetches tags for image', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ name: 'myimage', tags: ['v1', 'v2'] }),
        });

        const result = await registryGetTags('myimage');
        expect(result).toEqual({ name: 'myimage', tags: ['v1', 'v2'] });
      });
    });
  });

  // ===========================================================================
  // Trivy Handler Tests
  // ===========================================================================
  describe('Trivy handlers', () => {
    describe('trivyScanPath', () => {
      it('throws error for invalid path', async () => {
        await expect(trivyScanPath('')).rejects.toThrow('Invalid path provided');
        await expect(trivyScanPath('x')).rejects.toThrow('Invalid path provided');
      });

      it('scans path successfully', async () => {
        (global as unknown as MockGlobal).__mockExecResult = {
          stdout: JSON.stringify({ Results: [] }),
          stderr: '',
        };

        const result = await trivyScanPath('/valid/path');
        expect(result).toEqual({ Results: [] });
      });

      it('handles scan with vulnerabilities in stdout on error', async () => {
        (global as unknown as MockGlobal).__mockExecResult = {
          stdout: '',
          stderr: '',
          error: {
            message: 'Exit code 1',
            stdout: JSON.stringify({ Results: [{ Vulnerabilities: [] }] }),
          },
        };

        const result = await trivyScanPath('/valid/path');
        expect(result).toEqual({ Results: [{ Vulnerabilities: [] }] });
      });

      it('returns error object when stdout is not valid JSON', async () => {
        (global as unknown as MockGlobal).__mockExecResult = {
          stdout: '',
          stderr: '',
          error: {
            message: 'Exit code 1',
            stdout: 'not valid json',
          },
        };

        const result = await trivyScanPath('/valid/path');
        expect(result).toHaveProperty('error');
        expect(result).toHaveProperty('output', 'not valid json');
      });

      it('rethrows error when no stdout available', async () => {
        (global as unknown as MockGlobal).__mockExecResult = {
          stdout: '',
          stderr: '',
          error: {
            message: 'Command failed',
            stdout: undefined,
          },
        };

        await expect(trivyScanPath('/valid/path')).rejects.toThrow('Command failed');
      });
    });

    describe('trivyScanImage', () => {
      it('throws error for invalid image name', async () => {
        await expect(trivyScanImage('')).rejects.toThrow('Invalid image name provided');
        await expect(trivyScanImage('x')).rejects.toThrow('Invalid image name provided');
      });

      it('scans image successfully', async () => {
        (global as unknown as MockGlobal).__mockExecResult = {
          stdout: JSON.stringify({ Results: [] }),
          stderr: '',
        };

        const result = await trivyScanImage('nginx:latest');
        expect(result).toEqual({ Results: [] });
      });

      it('handles scan with vulnerabilities in stdout on error', async () => {
        (global as unknown as MockGlobal).__mockExecResult = {
          stdout: '',
          stderr: '',
          error: {
            message: 'Exit code 1',
            stdout: JSON.stringify({ Results: [{ Vulnerabilities: [] }] }),
          },
        };

        const result = await trivyScanImage('nginx:latest');
        expect(result).toEqual({ Results: [{ Vulnerabilities: [] }] });
      });

      it('returns error object when stdout is not valid JSON', async () => {
        (global as unknown as MockGlobal).__mockExecResult = {
          stdout: '',
          stderr: '',
          error: {
            message: 'Exit code 1',
            stdout: 'not valid json',
          },
        };

        const result = await trivyScanImage('nginx:latest');
        expect(result).toHaveProperty('error');
        expect(result).toHaveProperty('output');
      });
    });
  });

  // ===========================================================================
  // Combined Security Scan Tests
  // ===========================================================================
  describe('securityScanAll', () => {
    it('returns empty results when no parameters provided', async () => {
      const result = await securityScanAll();
      expect(result).toHaveProperty('timestamp');
      expect(result.trivy).toBeNull();
      expect(result.sonarqube).toBeNull();
      expect(result.dependencyTrack).toBeNull();
    });

    it('runs trivy scan when path provided', async () => {
      (global as unknown as MockGlobal).__mockExecResult = {
        stdout: JSON.stringify({ Results: [] }),
        stderr: '',
      };

      const result = await securityScanAll('/test/path');
      expect(result.trivy).toEqual({ Results: [] });
    });

    it('runs sonarqube scan when projectKey provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ issues: [] }),
      });

      const result = await securityScanAll(undefined, 'my-project');
      expect(result.sonarqube).toEqual({ issues: [] });
    });

    it('runs dependency-track scan when projectUuid provided', async () => {
      config.dependencyTrack.apiKey = 'test-key';
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([{ finding: 'test' }]),
      });

      const result = await securityScanAll(undefined, undefined, 'proj-uuid');
      expect(result.dependencyTrack).toEqual([{ finding: 'test' }]);
    });

    it('captures errors in results', async () => {
      mockFetch.mockRejectedValueOnce(new Error('API error'));

      const result = await securityScanAll(undefined, 'my-project');
      expect(result.sonarqube).toEqual({ error: 'API error' });
    });
  });

  // ===========================================================================
  // Platform Status Tests
  // ===========================================================================
  describe('checkPlatformStatus', () => {
    it('checks all services and returns status', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
      });

      const result = await checkPlatformStatus();
      expect(result).toHaveProperty('timestamp');
      expect(result).toHaveProperty('services');
      expect(Object.keys(result.services)).toContain('gitea');
      expect(Object.keys(result.services)).toContain('drone');
      expect(Object.keys(result.services)).toContain('sonarqube');
    });

    it('marks unhealthy services', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 503,
      });

      const result = await checkPlatformStatus();
      expect(result.services.gitea.status).toBe('unhealthy');
    });

    it('marks unreachable services', async () => {
      mockFetch.mockRejectedValue(new Error('Connection refused'));

      const result = await checkPlatformStatus();
      expect(result.services.gitea.status).toBe('unreachable');
      expect(result.services.gitea.error).toBe('Connection refused');
    });
  });
});
