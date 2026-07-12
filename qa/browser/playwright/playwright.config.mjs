import { defineConfig, devices } from '@playwright/test';

const TEST_ORIGIN_HOST = process.env.HYDRA_BROWSER_ORIGIN_HOST || '127.0.0.1';
const TEST_ORIGIN_PORT = process.env.HYDRA_BROWSER_ORIGIN_PORT || '4173';
const TEST_ORIGIN = process.env.HYDRA_BROWSER_TEST_ORIGIN
  || `http://${TEST_ORIGIN_HOST}:${TEST_ORIGIN_PORT}`;

const chromiumLaunchOptions = process.env.HYDRA_CHROMIUM_EXECUTABLE_PATH
  ? { executablePath: process.env.HYDRA_CHROMIUM_EXECUTABLE_PATH }
  : {};
const firefoxLaunchOptions = process.env.HYDRA_FIREFOX_EXECUTABLE_PATH
  ? { executablePath: process.env.HYDRA_FIREFOX_EXECUTABLE_PATH }
  : {};
const webkitLaunchOptions = process.env.HYDRA_WEBKIT_EXECUTABLE_PATH
  ? { executablePath: process.env.HYDRA_WEBKIT_EXECUTABLE_PATH }
  : {};

const projectDefinitions = new Map([
  ['chromium', {
    name: 'chromium',
    use: { ...devices['Desktop Chrome'], launchOptions: chromiumLaunchOptions }
  }],
  ['firefox', {
    name: 'firefox',
    use: { ...devices['Desktop Firefox'], launchOptions: firefoxLaunchOptions }
  }],
  ['webkit', {
    name: 'webkit',
    use: { ...devices['Desktop Safari'], launchOptions: webkitLaunchOptions }
  }],
  ['mobile-chromium', {
    name: 'mobile-chromium',
    use: { ...devices['Pixel 5'], launchOptions: chromiumLaunchOptions }
  }]
]);

const requestedProjectNames = (process.env.HYDRA_BROWSER_PROJECTS
  || 'chromium,firefox,mobile-chromium')
  .split(',')
  .map((name) => name.trim())
  .filter(Boolean);

const unknownProjects = requestedProjectNames.filter((name) => !projectDefinitions.has(name));
if (unknownProjects.length > 0) {
  throw new Error(`unknown HYDRA_BROWSER_PROJECTS value(s): ${unknownProjects.join(', ')}`);
}

const projects = requestedProjectNames.map((name) => projectDefinitions.get(name));

const workerCount = Number.parseInt(process.env.HYDRA_BROWSER_WORKERS || '1', 10);
if (!Number.isInteger(workerCount) || workerCount < 1) {
  throw new Error(`invalid HYDRA_BROWSER_WORKERS value: ${process.env.HYDRA_BROWSER_WORKERS}`);
}

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  fullyParallel: false,
  workers: workerCount,
  retries: process.env.CI ? 1 : 0,
  reporter: [
    ['list'],
    ['json', { outputFile: 'test-results/browser-lifecycle.json' }],
    ['html', { open: 'never', outputFolder: 'playwright-report' }]
  ],
  use: {
    baseURL: TEST_ORIGIN,
    screenshot: 'only-on-failure',
    trace: 'on-first-retry'
  },
  webServer: process.env.HYDRA_BROWSER_TEST_ORIGIN
    ? undefined
    : {
        command: 'node ./scripts/serve-test-origin.mjs',
        url: TEST_ORIGIN,
        reuseExistingServer: !process.env.CI,
        timeout: 15_000
      },
  projects
});
