import http from 'node:http';

const host = process.env.HYDRA_BROWSER_ORIGIN_HOST || '127.0.0.1';
const port = Number.parseInt(process.env.HYDRA_BROWSER_ORIGIN_PORT || '4173', 10);

if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  throw new Error(`invalid HYDRA browser test origin port: ${process.env.HYDRA_BROWSER_ORIGIN_PORT}`);
}

const page = Buffer.from(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>HYDRA browser lifecycle test origin</title></head>
<body><main id="hydra-browser-test-origin">HYDRA browser lifecycle test origin</main></body>
</html>\n`);

const server = http.createServer((request, response) => {
  if (request.url === '/favicon.ico') {
    response.writeHead(204);
    response.end();
    return;
  }

  response.writeHead(200, {
    'Cache-Control': 'no-store',
    'Content-Length': page.length,
    'Content-Type': 'text/html; charset=utf-8',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(page);
});

server.listen(port, host, () => {
  process.stdout.write(`HYDRA browser test origin listening at http://${host}:${port}\n`);
});

function shutdown() {
  server.close((error) => {
    if (error) {
      console.error(error);
      process.exitCode = 1;
    }
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
