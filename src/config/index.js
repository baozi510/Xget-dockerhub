import { PLATFORMS } from './platforms';

/**
 * @typedef {Object} SecurityConfig
 * @property {string[]} ALLOWED_METHODS - List of allowed HTTP methods
 * @property {string[]} ALLOWED_ORIGINS - List of allowed CORS origins
 * @property {number} MAX_PATH_LENGTH - Maximum allowed URL path length
 */

/**
 * @typedef {Object} ApplicationConfig
 * @property {number} TIMEOUT_SECONDS - Request timeout in seconds
 * @property {number} MAX_RETRIES - Maximum number of retry attempts
 * @property {number} RETRY_DELAY_MS - Delay between retries in milliseconds
 * @property {number} CACHE_DURATION - Cache duration in seconds
 * @property {SecurityConfig} SECURITY - Security-related configurations
 * @property {Object.<string, string>} PLATFORMS - Platform-specific configurations
 */

/** @type {ApplicationConfig} */
export const CONFIG = {
  TIMEOUT_SECONDS: 30,
  MAX_RETRIES: 3,
  RETRY_DELAY_MS: 1000,
  CACHE_DURATION: 1800, // 30 minutes
  SECURITY: {
    ALLOWED_METHODS: ['GET', 'HEAD'], // POST is allowed dynamically for Git operations
    ALLOWED_ORIGINS: ['*'],
    MAX_PATH_LENGTH: 2048
  },
  PLATFORMS
};
