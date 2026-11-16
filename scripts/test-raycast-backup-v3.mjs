import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, scryptSync } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { importTs } from './lib/ts-import.mjs';

const { decodeRaycastBackupV3, isRaycastBackupV3, normalizeRaycastBackupV3 } = await importTs(fileURLToPath(new URL('../src/main/raycast-backup-v3.ts', import.meta.url)));
const password = ' test passphrase ';
function fixture(payload, schemaVersion = 3) {
  const salt = Buffer.alloc(16, 1), iv = Buffer.alloc(16, 2);
  const key = scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(gzipSync(JSON.stringify(payload))), cipher.final(), cipher.getAuthTag()]);
  const header = gzipSync(JSON.stringify({ schemaVersion, appVersion: '2.12.1', encryption: { salt: salt.toString('hex'), iv: iv.toString('hex') } }));
  const length = Buffer.alloc(4); length.writeUInt32LE(header.length);
  return Buffer.concat([Buffer.from('RAYCFG3\n'), length, header, body]);
}
const backup = fixture({ quicklinks: { quicklinks: [{ id: 'link1', name: 'Search', link: 'https://example.com/?q={Query}' }] } });

test('RAYCFG3 authenticates, decompresses and maps the payload without trimming its password', () => {
  assert.equal(isRaycastBackupV3(backup), true);
  assert.equal(isRaycastBackupV3(Buffer.from('{}')), false);
  const decoded = decodeRaycastBackupV3(backup, password);
  assert.equal(decoded.raycast_version, '2.12.1');
  assert.equal(decoded.builtin_package_quicklinks.quicklinks[0].url, 'https://example.com/?q={argument}');
});
test('wrong passwords and tampered authentication tags cannot expose a payload', () => {
  assert.throws(() => decodeRaycastBackupV3(backup, password.trim()), /password is not valid/);
  const damaged = Buffer.from(backup); damaged[damaged.length - 1] ^= 1;
  assert.throws(() => decodeRaycastBackupV3(damaged, password), /damaged/);
});
test('malformed framing and unsupported schemas are format errors, not password errors', () => {
  const invalid = Buffer.from(backup); invalid.writeUInt32LE(0xffffffff, 8);
  assert.throws(() => decodeRaycastBackupV3(invalid, null), /truncated/);
  assert.throws(() => decodeRaycastBackupV3(backup.subarray(0, 20), null), /truncated/);
  assert.throws(() => decodeRaycastBackupV3(fixture({}, 4), null), /schema version/);
  assert.throws(() => decodeRaycastBackupV3(backup, null), /password is required/);
});
test('v3 category mapping joins extension IDs, preferences and AI messages', () => {
  const decoded = normalizeRaycastBackupV3({
    nodeExtensions: { extensions: [{ uuid: 'ext1', name: 'sample', author: 'author' }] },
    settings: { general: { globalHotkey: { kind: { type: 'SingleStep', shortcut: { modifiers: [{ modifier: 'Alt' }], key: { type: 'LayoutIndependent', code: 49 } } } } },
      nodeExtensions: [{ id: 'e:n:ext1', meta: { language: 'de' }, preferenceTypes: [{ name: 'language', type: 'textfield' }] }],
      commands: [{ id: 'c:n:ext1::-::index', extensionId: 'e:n:ext1', enabled: false, alias: 't' }, { id: 'c:r:applications::*::application::=::/Applications/Example.app' }],
      frecency: [{ itemId: 'c:r:applications::*::application::=::/Applications/Example.app', searchTerms: 'example' }] },
    ai: { chats: [{ id: 'chat1', title: 'Chat' }], messages: [{ chatId: 'chat1', role: 'user', content: { text: 'Hello' } }, { chatId: 'chat1', role: 'tool', content: { arguments: { secret: 'exclude' } } }] },
    snippets: { snippets: [{ title: 'Snippet', text: 'Text' }] }, notes: { notes: [{ text: 'Note' }] },
  });
  assert.equal(decoded.builtin_package_raycastPreferences.preferencesGeneral.raycastGlobalHotkey, 'Alt-49');
  assert.equal(decoded.builtin_package_rootSearch.rootSearch[0].key, 'extension_sample.index');
  assert.equal(decoded.builtin_package_rootSearch.rootSearch[1].path, '/Applications/Example.app');
  assert.equal(decoded.builtin_package_rootSearch.rootSearch[0].alias, 't');
  assert.equal(decoded.builtin_package_rootSearch.rootSearch.length, 2, 'search history must not become aliases');
  assert.equal(decoded.builtin_package_raycastExtensions.extensions[0].commands[0].enabled, false);
  assert.equal(decoded.builtin_package_raycastExtensions.extensions[0].prefs[0].value, 'de');
  assert.equal(decoded.builtin_package_snippets.snippets[0].name, 'Snippet');
  assert.equal(decoded['builtin_package_open-ai'].aiChats[0].messages.length, 1);
  assert.equal(decoded['builtin_package_open-ai'].aiChats[0].messages[0].content, 'Hello');
});

test('Raycast Meta is preserved as Command in clipboard and other multi-modifier shortcuts', () => {
  const shortcut = (modifiers, code = 8) => ({ kind: { type: 'SingleStep', shortcut: { modifiers, key: { type: 'LayoutIndependent', code } } } });
  const decoded = normalizeRaycastBackupV3({ settings: {
    general: { globalHotkey: shortcut([{ modifier: 'Meta' }, { modifier: 'Alt' }], 49) },
    commands: [
      { id: 'clipboard', macosHotkey: shortcut([{ modifier: 'Alt' }, { modifier: 'Meta' }]) },
      { id: 'shift', macosHotkey: shortcut([{ modifier: 'Meta' }, { modifier: 'Control' }, { modifier: 'Shift' }]) },
      { id: 'strings', macosHotkey: shortcut(['Meta', 'Alt']) },
      { id: 'unknown', macosHotkey: shortcut([{ modifier: 'Alt' }, { modifier: 'FutureModifier' }]) },
    ],
  } });
  assert.equal(decoded.builtin_package_raycastPreferences.preferencesGeneral.raycastGlobalHotkey, 'Command-Alt-49');
  const entries = decoded.builtin_package_rootSearch.rootSearch;
  assert.equal(entries[0].hotkey, 'Alt-Command-8');
  assert.equal(entries[1].hotkey, 'Command-Control-Shift-8');
  assert.equal(entries[2].hotkey, 'Command-Alt-8');
  assert.equal(entries[3].hotkey, undefined);
});
