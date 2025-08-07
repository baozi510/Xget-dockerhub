/**
 * Configuration object for different platform base URLs
 * @type {Object.<string, string>}
 */
export const PLATFORMS = {
  gh: 'https://github.com',
  gl: 'https://gitlab.com',
  gitea: 'https://gitea.com',
  codeberg: 'https://codeberg.org',
  sf: 'https://sourceforge.net',
  hf: 'https://huggingface.co',
  npm: 'https://registry.npmjs.org',
  pypi: 'https://pypi.org',
  'pypi-files': 'https://files.pythonhosted.org',
  conda: 'https://repo.anaconda.com',
  'conda-community': 'https://conda.anaconda.org',
  maven: 'https://repo1.maven.org',
  gradle: 'https://plugins.gradle.org',
  rubygems: 'https://rubygems.org',
  cran: 'https://cran.r-project.org',
  golang: 'https://proxy.golang.org',
  nuget: 'https://api.nuget.org',
  crates: 'https://crates.io',
  packagist: 'https://repo.packagist.org',
  debian: 'https://deb.debian.org',
  ubuntu: 'https://archive.ubuntu.com',
  fedora: 'https://dl.fedoraproject.org',
  rocky: 'https://download.rockylinux.org',
  opensuse: 'https://download.opensuse.org',
  arch: 'https://geo.mirror.pkgbuild.com',
  arxiv: 'https://arxiv.org',
  fdroid: 'https://f-droid.org',


  // Container Registries
  'cr-quay': 'https://quay.io',
  'cr-gcr': 'https://gcr.io',
  'cr-mcr': 'https://mcr.microsoft.com',
  'cr-ecr': 'https://public.ecr.aws',
  'cr-ghcr': 'https://ghcr.io',
  'cr-gitlab': 'https://registry.gitlab.com',
  'cr-redhat': 'https://registry.redhat.io',
  'cr-oracle': 'https://container-registry.oracle.com',
  'cr-cloudsmith': 'https://docker.cloudsmith.io',
  'cr-digitalocean': 'https://registry.digitalocean.com',
  'cr-vmware': 'https://projects.registry.vmware.com',
  'cr-k8s': 'https://registry.k8s.io',
  'cr-heroku': 'https://registry.heroku.com',
  'cr-suse': 'https://registry.suse.com',
  'cr-opensuse': 'https://registry.opensuse.org',
  'cr-gitpod': 'https://registry.gitpod.io',
  'cr-dockerhub': 'https://registry-1.docker.io',
};

/**
 * Unified path transformation function
 * @param {string} path - The original path
 * @param {string} platformKey - The platform key
 * @returns {string} - The transformed path
 */
export function transformPath(path, platformKey) {
  if (!PLATFORMS[platformKey]) {
    return path;
  }

  const prefix = `/${platformKey.replace(/-/g, '/')}/`;
  let transformedPath = path.replace(
    new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`),
    '/'
  );

  // Special handling for crates.io API paths
  if (platformKey === 'crates') {
    // Transform paths to include the API prefix
    if (transformedPath.startsWith('/')) {
      // Handle different API endpoints:
      // /serde/1.0.0/download -> /api/v1/crates/serde/1.0.0/download
      // /serde -> /api/v1/crates/serde
      // /?q=query -> /api/v1/crates?q=query
      if (transformedPath === '/' || transformedPath.startsWith('/?')) {
        // Search endpoint
        transformedPath = transformedPath.replace('/', '/api/v1/crates');
      } else {
        // Crate-specific endpoints
        transformedPath = `/api/v1/crates${transformedPath}`;
      }
    }
  }

  return transformedPath;
}
