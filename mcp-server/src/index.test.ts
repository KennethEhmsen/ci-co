import { describe, it, expect } from 'vitest';
import { validateSeverity, sanitizePath, sanitizeImageName } from './index.js';

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
