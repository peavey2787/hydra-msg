import { spawnSync } from 'node:child_process';

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

const args = ['playwright', 'install'];
if (process.env.HYDRA_PLAYWRIGHT_INSTALL_DEPS === '1') {
  args.push('--with-deps');
}
args.push(...browsers);

const command = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const result = spawnSync(command, args, { stdio: 'inherit' });
if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
