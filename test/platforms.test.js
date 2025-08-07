import { describe, expect, it } from 'vitest';
import { PLATFORMS, transformPath } from '../src/config/platforms.js';

describe('Platform Configuration', () => {
  describe('Platform Definitions', () => {
    it('should have all required platforms defined', () => {
      const requiredPlatforms = [
        'gh',
        'gl',
        'sf',
        'gitea',
        'codeberg',
        'hf',
        'npm',
        'pypi',
        'conda'
      ];

      requiredPlatforms.forEach(platform => {
        expect(PLATFORMS).toHaveProperty(platform);
        expect(PLATFORMS[platform]).toBeDefined();
      });
    });

    it('should have valid base URLs for all platforms', () => {
      Object.values(PLATFORMS).forEach(baseUrl => {
        expect(baseUrl).toBeDefined();
        expect(baseUrl).toMatch(/^https?:\/\/.+/);
      });
    });

    it('should have unified transform function', () => {
      expect(transformPath).toBeDefined();
      expect(typeof transformPath).toBe('function');
    });
  });

  describe('Unified Transform Function', () => {
    it('should transform GitHub paths correctly', () => {
      expect(transformPath('/gh/microsoft/vscode/archive/main.zip', 'gh')).toBe(
        '/microsoft/vscode/archive/main.zip'
      );

      expect(transformPath('/gh/user/repo.git', 'gh')).toBe('/user/repo.git');
    });

    it('should transform GitLab paths correctly', () => {
      expect(transformPath('/gl/gitlab-org/gitlab/-/archive/master/gitlab-master.zip', 'gl')).toBe(
        '/gitlab-org/gitlab/-/archive/master/gitlab-master.zip'
      );
    });

    it('should transform SourceForge paths correctly', () => {
      expect(
        transformPath('/sf/projects/sevenzip/files/7-Zip/23.01/7z2301-x64.exe/download', 'sf')
      ).toBe('/projects/sevenzip/files/7-Zip/23.01/7z2301-x64.exe/download');
    });

    it('should transform Gitea paths correctly', () => {
      expect(transformPath('/gitea/gitea/gitea/archive/master.zip', 'gitea')).toBe(
        '/gitea/gitea/archive/master.zip'
      );
    });

    it('should transform Codeberg paths correctly', () => {
      expect(transformPath('/codeberg/forgejo/forgejo/archive/forgejo.zip', 'codeberg')).toBe(
        '/forgejo/forgejo/archive/forgejo.zip'
      );
    });

    it('should transform Hugging Face paths correctly', () => {
      expect(transformPath('/hf/microsoft/DialoGPT-medium/resolve/main/config.json', 'hf')).toBe(
        '/microsoft/DialoGPT-medium/resolve/main/config.json'
      );

      expect(transformPath('/hf/datasets/squad/resolve/main/train.json', 'hf')).toBe(
        '/datasets/squad/resolve/main/train.json'
      );
    });

    it('should transform npm paths correctly', () => {
      expect(transformPath('/npm/react/-/react-18.2.0.tgz', 'npm')).toBe(
        '/react/-/react-18.2.0.tgz'
      );
      expect(transformPath('/npm/lodash', 'npm')).toBe('/lodash');
    });

    it('should transform PyPI paths correctly', () => {
      expect(transformPath('/pypi/packages/source/r/requests/requests-2.31.0.tar.gz', 'pypi')).toBe(
        '/packages/source/r/requests/requests-2.31.0.tar.gz'
      );

      expect(transformPath('/pypi/simple/requests/', 'pypi')).toBe('/simple/requests/');
    });

    it('should transform PyPI files paths correctly', () => {
      expect(
        transformPath('/pypi/files/packages/source/r/requests/requests-2.31.0.tar.gz', 'pypi-files')
      ).toBe('/packages/source/r/requests/requests-2.31.0.tar.gz');
    });

    it('should transform conda default channel paths correctly', () => {
      expect(transformPath('/conda/pkgs/main/linux-64/numpy-1.24.3.conda', 'conda')).toBe(
        '/pkgs/main/linux-64/numpy-1.24.3.conda'
      );
    });

    it('should transform conda community channel paths correctly', () => {
      expect(
        transformPath('/conda/community/conda-forge/linux-64/repodata.json', 'conda-community')
      ).toBe('/conda-forge/linux-64/repodata.json');
    });

    it('should transform container registry paths correctly', () => {
      expect(
        transformPath('/cr/ghcr/v2/nginxinc/nginx-unprivileged/manifests/latest', 'cr-ghcr')
      ).toBe('/v2/nginxinc/nginx-unprivileged/manifests/latest');

      expect(transformPath('/cr/gcr/v2/distroless/base/manifests/latest', 'cr-gcr')).toBe(
        '/v2/distroless/base/manifests/latest'
      );
    });
  });

  describe('Platform Base URLs', () => {
    it('should have correct GitHub base URL', () => {
      expect(PLATFORMS.gh).toBe('https://github.com');
    });

    it('should have correct GitLab base URL', () => {
      expect(PLATFORMS.gl).toBe('https://gitlab.com');
    });

    it('should have correct SourceForge base URL', () => {
      expect(PLATFORMS.sf).toBe('https://sourceforge.net');
    });

    it('should have correct Gitea base URL', () => {
      expect(PLATFORMS.gitea).toBe('https://gitea.com');
    });

    it('should have correct Codeberg base URL', () => {
      expect(PLATFORMS.codeberg).toBe('https://codeberg.org');
    });

    it('should have correct Hugging Face base URL', () => {
      expect(PLATFORMS.hf).toBe('https://huggingface.co');
    });

    it('should have correct npm base URL', () => {
      expect(PLATFORMS.npm).toBe('https://registry.npmjs.org');
    });

    it('should have correct PyPI base URL', () => {
      expect(PLATFORMS.pypi).toBe('https://pypi.org');
    });

    it('should have correct PyPI files base URL', () => {
      expect(PLATFORMS['pypi-files']).toBe('https://files.pythonhosted.org');
    });

    it('should have correct conda base URLs', () => {
      expect(PLATFORMS.conda).toBe('https://repo.anaconda.com');
      expect(PLATFORMS['conda-community']).toBe('https://conda.anaconda.org');
    });

    it('should have correct container registry base URLs', () => {
      expect(PLATFORMS['cr-ghcr']).toBe('https://ghcr.io');
      expect(PLATFORMS['cr-gcr']).toBe('https://gcr.io');
      expect(PLATFORMS['cr-mcr']).toBe('https://mcr.microsoft.com');
    });
  });

  describe('Path Transformation Edge Cases', () => {
    it('should handle empty paths gracefully', () => {
      Object.keys(PLATFORMS).forEach(key => {
        expect(() => transformPath('', key)).not.toThrow();
      });
    });

    it('should handle paths without platform prefix', () => {
      Object.keys(PLATFORMS).forEach(key => {
        const testPath = '/some/random/path';
        expect(() => transformPath(testPath, key)).not.toThrow();
      });
    });

    it('should handle unknown platform keys', () => {
      const testPath = '/unknown/test/path';
      expect(transformPath(testPath, 'unknown')).toBe(testPath);
    });

    it('should handle paths with query parameters', () => {
      expect(transformPath('/gh/user/repo/file.txt?ref=main', 'gh')).toBe(
        '/user/repo/file.txt?ref=main'
      );
    });

    it('should handle paths with fragments', () => {
      expect(transformPath('/gh/user/repo/README.md#section', 'gh')).toBe(
        '/user/repo/README.md#section'
      );
    });
  });

  describe('URL Construction', () => {
    it('should construct valid URLs for all platforms', () => {
      Object.entries(PLATFORMS).forEach(([key, baseUrl]) => {
        const testPath = `/${key.replace('-', '/')}/test/path`;
        const transformedPath = transformPath(testPath, key);
        const fullUrl = baseUrl + transformedPath;

        expect(() => new URL(fullUrl)).not.toThrow();
      });
    });

    it('should handle container registry URL construction', () => {
      const testPath = '/cr/ghcr/v2/nginxinc/nginx-unprivileged/manifests/latest';
      const transformedPath = transformPath(testPath, 'cr-ghcr');
      const fullUrl = PLATFORMS['cr-ghcr'] + transformedPath;

      expect(() => new URL(fullUrl)).not.toThrow();
      expect(fullUrl).toBe('https://ghcr.io/v2/nginxinc/nginx-unprivileged/manifests/latest');
    });
  });

  describe('Container Registry Support', () => {
    it('should have all major container registries defined', () => {
      const containerRegistries = [
        'cr-quay',
        'cr-gcr',
        'cr-mcr',
        'cr-ecr',
        'cr-ghcr',
        'cr-gitlab',
        'cr-redhat',
        'cr-oracle',
        'cr-cloudsmith',
        'cr-digitalocean',
        'cr-vmware',
        'cr-k8s',
        'cr-heroku',
        'cr-suse',
        'cr-opensuse',
        'cr-gitpod'
      ];

      containerRegistries.forEach(registry => {
        expect(PLATFORMS).toHaveProperty(registry);
        expect(PLATFORMS[registry]).toBeDefined();
        expect(typeof PLATFORMS[registry]).toBe('string');
      });
    });

    it('should transform all container registry paths correctly', () => {
      const containerRegistries = [
        'cr-quay',
        'cr-gcr',
        'cr-mcr',
        'cr-ecr',
        'cr-ghcr',
        'cr-gitlab',
        'cr-redhat',
        'cr-oracle',
        'cr-cloudsmith',
        'cr-digitalocean',
        'cr-vmware',
        'cr-k8s',
        'cr-heroku',
        'cr-suse',
        'cr-opensuse',
        'cr-gitpod'
      ];

      containerRegistries.forEach(registry => {
        const prefix = registry.replace('cr-', 'cr/');
        const testPath = `/${prefix}/v2/test/image/manifests/latest`;
        const transformedPath = transformPath(testPath, registry);
        expect(transformedPath).toBe('/v2/test/image/manifests/latest');
      });
    });
  });
});
