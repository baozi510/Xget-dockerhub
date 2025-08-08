import { CONFIG } from './config/index.js';
import { transformPath } from './config/platforms.js';

/**
 * Monitors performance metrics during request processing
 */
class PerformanceMonitor {
  /**
   * Initializes a new performance monitor
   */
  constructor() {
    this.startTime = Date.now();
    this.marks = new Map();
  }

  /**
   * Records a named performance mark
   * @param {string} name - The name of the performance mark
   */
  mark(name) {
    if (this.marks.has(name)) {
      console.warn(`Mark with name ${name} already exists.`);
    }
    this.marks.set(name, Date.now() - this.startTime);
  }

  /**
   * Gets all recorded performance metrics
   * @returns {Record<string, number>} A dictionary of performance metrics
   */
  getMetrics() {
    return Object.fromEntries(this.marks.entries());
  }
}

/**
 * Detects if a request is a Docker container registry operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a Docker registry operation
 */
function isDockerRequest(request, url) {
  // Check for container registry API endpoints
  if (url.pathname.startsWith('/v2/')) {
    return true;
  }

  // Check for Docker-specific User-Agent
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.toLowerCase().includes('docker/')) {
    return true;
  }

  // Check for Docker-specific Accept headers
  const accept = request.headers.get('Accept') || '';
  if (
    accept.includes('application/vnd.docker.distribution.manifest') ||
    accept.includes('application/vnd.oci.image.manifest') ||
    accept.includes('application/vnd.docker.image.rootfs.diff.tar.gzip')
  ) {
    return true;
  }

  // Check for Docker-specific Docker-Distribution-Api-Version header
  const apiVersion = request.headers.get('Docker-Distribution-Api-Version') || '';
  if (apiVersion.includes('registry/2.0')) {
    return true;
  }

  return false;
}

/**
 * Detects if a request is a Git operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a Git operation
 */
function isGitRequest(request, url) {
  // Check for Git-specific endpoints
  if (url.pathname.endsWith('/info/refs')) {
    return true;
  }

  if (url.pathname.endsWith('/git-upload-pack') || url.pathname.endsWith('/git-receive-pack')) {
    return true;
  }

  // Check for Git user agents (more comprehensive detection)
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.includes('git/') || userAgent.startsWith('git/')) {
    return true;
  }

  // Check for Git service parameter often used in info/refs requests
  const serviceParam = url.searchParams.get('service') || '';
  if (serviceParam === 'git-upload-pack' || serviceParam === 'git-receive-pack') {
    return true;
  }

  // Check for Git-specific content types
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('git-upload-pack') || contentType.includes('git-receive-pack')) {
    return true;
  }

  return false;
}

/**
 * Validates incoming requests against security rules
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {{valid: boolean, error?: string, status?: number}} Validation result
 */
function validateRequest(request, url) {
  const isGit = isGitRequest(request, url);
  const isDocker = isDockerRequest(request, url);

  // Allow only specific methods (more permissive for Git/Docker which need POST/PUT/PATCH)
  const allowedMethods = isGit || isDocker ? ['GET', 'HEAD', 'POST', 'PUT', 'PATCH'] : CONFIG.SECURITY.ALLOWED_METHODS;
  if (!allowedMethods.includes(request.method)) {
    return { valid: false, error: 'Method not allowed', status: 405 };
  }

  // Validate path length
  if (url.pathname.length > CONFIG.SECURITY.MAX_PATH_LENGTH) {
    return { valid: false, error: 'Path too long', status: 414 };
  }

  return { valid: true };
}

/**
 * Adds security headers to the response
 * @param {Headers} headers - Headers object to modify
 * @returns {Headers} Modified headers with security policies applied
 */
function addSecurityHeaders(headers) {
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Content-Security-Policy', "default-src 'none'; img-src 'self'; script-src 'none'");
  headers.set('Permissions-Policy', 'interest-cohort=()');
  return headers;
}

/** 识别 /v2/<repo>/(manifests|blobs|tags) 的镜像模式路径（不以 /v2/cr/ 开头） */
function isMirrorDockerPath(pathname) {
  return /^\/v2\/(?!cr\/)(.+?)\/(manifests|blobs|tags)\b/.test(pathname);
}

/** 上游代理（流式转发 + 401 原样透传 + 3xx Location 重写）——仅给 Docker 用 */
async function proxyDockerUpstream(request, upstreamUrl) {
  const upstream = await fetch(upstreamUrl, {
    method: request.method,
    headers: request.headers,
    body: (request.method === 'GET' || request.method === 'HEAD') ? undefined : request.body,
    redirect: 'manual'
  });

  // 1) 401：原样透传挑战头，让客户端自己去 auth.docker.io
  if (upstream.status === 401) {
    return new Response(upstream.body, { status: 401, headers: upstream.headers });
  }

  // 2) 3xx：把 registry-1 的 Location 改回你的域名，阻止跳出镜像
  if (upstream.status >= 300 && upstream.status < 400) {
    const loc = upstream.headers.get('Location');
    if (loc) {
      const reqUrl = new URL(request.url);
      const u = new URL(loc);
      if (u.hostname === 'registry-1.docker.io') {
        u.protocol = reqUrl.protocol;
        u.host = reqUrl.host; // 回写成 hxorz.cn
        const h = new Headers(upstream.headers);
        h.set('Location', u.toString());
        return new Response(null, { status: upstream.status, headers: h });
      }
    }
    return new Response(upstream.body, { status: upstream.status, headers: upstream.headers });
  }

  // 3) 其余：保持原样、流式转发（不额外加头，协议更干净）
  return new Response(upstream.body, { status: upstream.status, headers: upstream.headers });
}

/**
 * Parses WWW-Authenticate header for container registry
 * @param {string} authenticateStr - The WWW-Authenticate header string
 * @returns {{realm: string, service: string}} Parsed authentication info
 */
function parseAuthenticate(authenticateStr) {
  // sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (matches == null || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1]
  };
}

/**
 * Fetches authentication token from container registry
 * @param {{realm: string, service: string}} wwwAuthenticate - Authentication info
 * @param {string} scope - The scope for the token
 * @param {string} authorization - Authorization header value
 * @returns {Promise<Response>} Token response
 */
async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service.length) {
    url.searchParams.set('service', wwwAuthenticate.service);
  }
  if (scope) {
    url.searchParams.set('scope', scope);
  }
  const headers = new Headers();
  if (authorization) {
    headers.set('Authorization', authorization);
  }
  const resp = await fetch(url.toString(), { headers, redirect: 'follow' });
  return resp;
}

async function handleRequest(request, env, ctx) {
  try {
    const url = new URL(request.url);
    const isDocker = isDockerRequest(request, url);

    const monitor = new PerformanceMonitor();

    // Handle Docker API version check
    if (isDocker && (url.pathname === '/v2/' || url.pathname === '/v2')) {
      const headers = new Headers({
        'Docker-Distribution-Api-Version': 'registry/2.0',
        'Content-Type': 'application/json'
      });
      addSecurityHeaders(headers);
      return new Response('{}', { status: 200, headers });
    }

    // Redirect root path or invalid platforms to GitHub repository
    if (url.pathname === '/' || url.pathname === '') {
      const HOME_PAGE_URL = 'https://inwpu.github.io';
      return Response.redirect(HOME_PAGE_URL, 302);
    }

    const validation = validateRequest(request, url);
    if (!validation.valid) {
      return new Response(validation.error, {
        status: validation.status,
        headers: addSecurityHeaders(new Headers())
      });
    }

    // Parse platform and path
    let platform;
    let effectivePath = url.pathname;

    // Handle container registry paths specially
    if (isDocker) {
      // ① 镜像模式优先：/v2/<repo>/(manifests|blobs|tags) 直接代理 Docker Hub
      if (isMirrorDockerPath(url.pathname)) {
        const upstreamUrl = `https://registry-1.docker.io${url.pathname}${url.search}`;
        return proxyDockerUpstream(request, upstreamUrl);
      }

      // ② 显式模式短路：/v2/cr/dockerhub/<repo>/... 或 /cr/dockerhub/<repo>/...
      if (url.pathname.startsWith('/v2/cr/dockerhub/') || url.pathname.startsWith('/cr/dockerhub/')) {
        const rewritten = url.pathname
          .replace(/^\/v2\/cr\/dockerhub\//, '/v2/')
          .replace(/^\/cr\/dockerhub\//, '/v2/');
        const upstreamUrl = `https://registry-1.docker.io${rewritten}${url.search}`;
        return proxyDockerUpstream(request, upstreamUrl);
      }

      // ③ 其余显式平台：必须带 /cr/ 前缀
      if (!url.pathname.startsWith('/cr/') && !url.pathname.startsWith('/v2/cr/')) {
        return new Response('container registry requests must use /cr/ prefix', {
          status: 400,
          headers: addSecurityHeaders(new Headers())
        });
      }

      // 显式模式下供后续解析的平台路径：移除开头的 /v2
      effectivePath = url.pathname.replace(/^\/v2/, '');
    }

    // Platform detection using transform patterns
    // Sort platforms by path length (descending) to prioritize more specific paths
    const sortedPlatforms = Object.keys(CONFIG.PLATFORMS).sort((a, b) => {
      const pathA = `/${a.replace('-', '/')}/`;
      const pathB = `/${b.replace('-', '/')}/`;
      return pathB.length - pathA.length;
    });

    // Try to match the path to a platform using unified logic
    platform =
      sortedPlatforms.find(key => {
        const expectedPrefix = `/${key.replace('-', '/')}/`;
        return effectivePath.startsWith(expectedPrefix);
      }) || effectivePath.split('/')[1];

    if (!platform || !CONFIG.PLATFORMS[platform]) {
      const HOME_PAGE_URL = 'https://inwpu.github.io';
      return Response.redirect(HOME_PAGE_URL, 302);
    }

    // Transform URL based on platform using unified logic
    const targetPath = transformPath(effectivePath, platform);

    // For container registries, ensure we add the /v2 prefix for the Docker API
    let finalTargetPath;
    if (platform.startsWith('cr-')) {
      finalTargetPath = targetPath.startsWith('/v2/') ? targetPath : `/v2${targetPath}`;
    } else {
      finalTargetPath = targetPath;
    }

    const targetUrl = `${CONFIG.PLATFORMS[platform]}${finalTargetPath}${url.search}`;
    const authorization = request.headers.get('Authorization');

    // Handle Docker authentication
    if (isDocker && url.pathname === '/v2/auth') {
      const newUrl = new URL(CONFIG.PLATFORMS[platform] + '/v2/');
      const resp = await fetch(newUrl.toString(), {
        method: 'GET',
        redirect: 'follow'
      });
      if (resp.status !== 401) {
        return resp;
      }
      const authenticateStr = resp.headers.get('WWW-Authenticate');
      if (authenticateStr === null) {
        return resp;
      }
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get('scope');
      return await fetchToken(wwwAuthenticate, scope || '', authorization || '');
    }

    // Check if this is a Git operation
    const isGit = isGitRequest(request, url);

    // Check cache first (skip cache for Git and Docker operations)
    // @ts-ignore
    const cache = caches.default;
    const cacheKey = new Request(targetUrl, request);
    let response;

    if (!isGit && !isDocker) {
      response = await cache.match(cacheKey);
      if (response) {
        monitor.mark('cache_hit');
        return response;
      }
    }

    // Prepare fetch options
    /** @type {RequestInit & {cf?: any}} */
    const fetchOptions = {
      method: request.method,
      headers: new Headers(),
      redirect: 'follow'
    };

    // Add body for POST/PUT/PATCH requests (Git/Docker operations)
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && (isGit || isDocker)) {
      fetchOptions.body = request.body;
    }

    // Cast headers to Headers for proper typing
    const requestHeaders = /** @type {Headers} */ (fetchOptions.headers);

    // Set appropriate headers for Git/Docker vs regular requests
    if (isGit || isDocker) {
      // For Git/Docker operations, copy all headers from the original request
      // This ensures protocol compliance
      for (const [key, value] of request.headers.entries()) {
        // Skip headers that might cause issues with proxying
        if (!['host', 'connection', 'upgrade', 'proxy-connection'].includes(key.toLowerCase())) {
          requestHeaders.set(key, value);
        }
      }

      // Set Git-specific headers if not present
      if (isGit && !requestHeaders.has('User-Agent')) {
        requestHeaders.set('User-Agent', 'git/2.34.1');
      }

      // For Git upload-pack requests, ensure proper content type
      if (isGit && request.method === 'POST' && url.pathname.endsWith('/git-upload-pack')) {
        if (!requestHeaders.has('Content-Type')) {
          requestHeaders.set('Content-Type', 'application/x-git-upload-pack-request');
        }
        requestHeaders.set('Accept', 'application/x-git-upload-pack-result');
      }

      // Remove encoding headers that might conflict with proxying
      requestHeaders.delete('Accept-Encoding');
      requestHeaders.delete('Content-Length');
      requestHeaders.delete('Transfer-Encoding');

      // Explicitly set connection headers for Git/Docker operations
      requestHeaders.set('Connection', 'keep-alive');
    } else {
      // Enable Cloudflare optimization for non-Git/Docker requests
      Object.assign(fetchOptions, {
        cf: {
          http3: true,
          cacheTtl: CONFIG.CACHE_DURATION,
          cacheEverything: true,
          minify: {
            javascript: true,
            css: true,
            html: true
          },
          preconnect: true
        }
      });

      // Set appropriate headers for regular requests to improve caching
      requestHeaders.set('Accept-Encoding', 'gzip, deflate, br');
      requestHeaders.set('Connection', 'keep-alive');
      requestHeaders.set('User-Agent', 'Wget/1.21.3');
      requestHeaders.set('Origin', request.headers.get('Origin') || '*');

      // Handle range requests
      const rangeHeader = request.headers.get('Range');
      if (rangeHeader) {
        requestHeaders.set('Range', rangeHeader);
      }
    }

    // Implement retry mechanism
    let attempts = 0;
    while (attempts < CONFIG.MAX_RETRIES) {
      try {
        monitor.mark('attempt_' + attempts);

        // Create a controller to enforce request timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.TIMEOUT_SECONDS * 1000);

        // Perform the fetch with the signal for timeout support
        const finalFetchOptions =
          isGit || isDocker
            ? { ...fetchOptions, signal: controller.signal }
            : { ...fetchOptions, signal: controller.signal };

        response = await fetch(targetUrl, finalFetchOptions);

        clearTimeout(timeoutId);

        if (response.ok || response.status === 206) {
          monitor.mark('success');
          break;
        }

        // Docker 401：原样透传挑战头，让客户端自行获取 token
        if (isDocker && response.status === 401) {
          monitor.mark('docker_auth_passthrough');
          return new Response(response.body, { status: 401, headers: response.headers });
        }

        // Don't retry on client errors (4xx) - these won't improve with retries
        if (response.status >= 400 && response.status < 500) {
          monitor.mark('client_error');
          break;
        }

        attempts++;
        if (attempts < CONFIG.MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY_MS * attempts));
        }
      } catch (error) {
        attempts++;
        if (error instanceof Error && error.name === 'AbortError') {
          return new Response('Request timeout', {
            status: 408,
            headers: addSecurityHeaders(new Headers())
          });
        }
        if (attempts >= CONFIG.MAX_RETRIES) {
          const message = error instanceof Error ? error.message : String(error);
          return new Response(`Failed after ${CONFIG.MAX_RETRIES} attempts: ${message}`, {
            status: 500,
            headers: addSecurityHeaders(new Headers())
          });
        }
        // Wait before retrying
        await new Promise(resolve => setTimeout(resolve, CONFIG.RETRY_DELAY_MS * attempts));
      }
    }

    // Check if we have a valid response after all attempts
    if (!response) {
      return new Response('No response received after all retry attempts', {
        status: 500,
        headers: addSecurityHeaders(new Headers())
      });
    }

    // If response is still not ok after all retries, return the error
    if (!response.ok && response.status !== 206) {
      // For Docker authentication errors that we couldn't resolve with anonymous tokens,
      // return a more helpful error message
      if (isDocker && response.status === 401) {
        const errorText = await response.text().catch(() => '');
        return new Response(
          `Authentication required for this container registry request. This may be a private repository. Original error: ${errorText}`,
          {
            status: 401,
            headers: addSecurityHeaders(new Headers())
          }
        );
      }
      const errorText = await response.text().catch(() => 'Unknown error');
      return new Response(`Upstream server error (${response.status}): ${errorText}`, {
        status: response.status,
        headers: addSecurityHeaders(new Headers())
      });
    }

    // Handle URL rewriting for different platforms
    let responseBody = response.body;

    // Handle PyPI index rewriting
    if (platform === 'pypi' && response.headers.get('content-type')?.includes('text/html')) {
      const originalText = await response.text();

      // Rewrite URLs in the response body to go through the Cloudflare Worker
      // files.pythonhosted.org URLs should be rewritten to go through our pypi/files endpoint
      const rewrittenText = originalText.replace(
        /https:\/\/files\.pythonhosted\.org/g,
        `${url.origin}/pypi/files`
      );
      responseBody = rewrittenText;
    }

    // Handle npm registry URL rewriting
    if (platform === 'npm' && response.headers.get('content-type')?.includes('application/json')) {
      const originalText = await response.text();
      // Rewrite tarball URLs in npm registry responses to go through our npm endpoint
      // https://registry.npmjs.org/package/-/package-version.tgz -> https://xget.xi-xu.me/npm/package/-/package-version.tgz
      const rewrittenText = originalText.replace(
        /https:\/\/registry\.npmjs\.org\/([^\/]+)/g,
        `${url.origin}/npm/$1`
      );
      responseBody = rewrittenText;
    }

    // Prepare response headers
    const headers = new Headers(response.headers);

    if (isGit || isDocker) {
      // For Git/Docker operations, preserve all headers from the upstream response
      // These protocols are very sensitive to header changes
      // Don't add any additional headers that might interfere with protocol operation
      // The response headers from upstream should be passed through as-is
    } else {
      // For regular requests, add security and caching headers
      headers.set('Cache-Control', `public, max-age=${CONFIG.CACHE_DURATION}`);
      headers.set('X-Content-Type-Options', 'nosniff');
      headers.set('Accept-Ranges', 'bytes');
      addSecurityHeaders(headers);
    }

    // Create final response
    const finalResponse = new Response(responseBody, {
      status: response.status,
      headers
    });

    // Cache successful responses for non-Git/Docker requests
    if (!isGit && !isDocker && (response.ok || response.status === 206)) {
      ctx.waitUntil(cache.put(cacheKey, finalResponse.clone()));
    }

    monitor.mark('complete');

    // For Git/Docker operations, return response directly
    if (isGit || isDocker) {
      return finalResponse;
    }

    // For regular requests, add performance metrics header
    return addPerformanceHeaders(finalResponse, monitor);
  } catch (error) {
    console.error('Error handling request:', error);
    const message = error instanceof Error ? error.message : String(error);
    return new Response(`Internal Server Error: ${message}`, {
      status: 500,
      headers: addSecurityHeaders(new Headers())
    });
  }
}

/**
 * Adds performance metrics to the response headers
 * @param {Response} response - The response object to modify
 * @param {PerformanceMonitor} monitor - The performance monitor instance used throughout the request
 * @returns {Response} The modified response with performance metrics
 */
function addPerformanceHeaders(response, monitor) {
  const headers = new Headers(response.headers);
  headers.set('X-Performance-Metrics', JSON.stringify(monitor.getMetrics()));
  addSecurityHeaders(headers);
  return new Response(response.body, { status: response.status, headers });
}

export default {
  /**
   * Main entry point for the Cloudflare Worker
   * @param {Request} request - The incoming request
   * @param {Object} env - Environment variables
   * @param {ExecutionContext} ctx - Cloudflare Workers execution context
   * @returns {Promise<Response>} The response object
   */
  fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};
