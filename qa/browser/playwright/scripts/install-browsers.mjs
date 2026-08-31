import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const projectToBrowser = new Map([
  ['chromium', 'chromium'],
  ['firefox', 'firefox'],
  ['webkit', 'webkit'],
  ['mobile-chromium', 'chromium']
]);

const projects = (process.env.HYDRA_BROWSER_PROJECTS
  || 'chromium,firefox,mobile-chromium')
  .split(',')
  .map((name) => name.trim())
  .filter(Boolean);

const browsers = [];
for (const project of projects) {
  const browser = projectToBrowser.get(project);
  if (!browser) {
    throw new Error(`unknown HYDRA_BROWSER_PROJECTS value: ${project}`);
  }
  if (!browsers.includes(browser)) {
    browsers.push(browser);
  }
}

if (browsers.length === 0) {
  throw new Error('HYDRA_BROWSER_PROJECTS selected no browser projects');
}

const args = ['install'];
if (process.env.HYDRA_PLAYWRIGHT_INSTALL_DEPS === '1') {
  args.push('--with-deps');
}
args.push(...browsers);

// Invoke the pinned local Playwright CLI through the current Node executable.
// On Windows, spawning npx.cmd directly can fail with EINVAL under Node 22.
const playwrightCli = fileURLToPath(new URL('../node_modules/playwright/cli.js', import.meta.url));
if (!existsSync(playwrightCli)) {
  throw new Error(`local Playwright CLI is missing after npm ci: ${playwrightCli}`);
}
const result = spawnSync(process.execPath, [playwrightCli, ...args], { stdio: 'inherit' });
if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
