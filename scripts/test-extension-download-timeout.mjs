import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import vm from 'node:vm';
import { transform } from 'esbuild';

test('a stalled extension response aborts and rejects instead of blocking the import', async () => {
  const source = fs.readFileSync(new URL('../src/main/extension-registry.ts', import.meta.url), 'utf8');
  const start = source.indexOf('async function downloadAndExtractTarball(');
  const end = source.indexOf('\n/**', start);
  const { code } = await transform(source.slice(start, end), { loader: 'ts', format: 'cjs' });
  const context = vm.createContext({
    URL, Buffer,
    require: () => ({ get: (url, options, callback) => http.get(url, { ...options, timeout: 30 }, callback) }),
    extractTarGz: () => { throw new Error('Incomplete response must not be extracted'); },
  });
  vm.runInContext(code, context);
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/gzip' });
    response.write('partial download');
    // Keep the connection open without sending more bytes.
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let deadline;
  try {
    await assert.rejects(Promise.race([
      context.downloadAndExtractTarball(`http://127.0.0.1:${server.address().port}/bundle`, '/unused'),
      new Promise((_resolve, reject) => { deadline = setTimeout(() => reject(new Error('Import stayed blocked')), 2000); }),
    ]), /Extension download timed out/);
  } finally {
    clearTimeout(deadline);
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
