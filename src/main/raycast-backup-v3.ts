import { createDecipheriv, scryptSync } from 'crypto';
import { gunzipSync } from 'zlib';

const MAGIC = Buffer.from('RAYCFG3\n');
const MAX_HEADER = 1024 * 1024;
const MAX_PAYLOAD = 512 * 1024 * 1024;
type RecordValue = Record<string, any>;
const record = (value: any): RecordValue => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const list = (value: any): RecordValue[] => Array.isArray(value) ? value.filter((item) => item && typeof item === 'object') : [];

export function isRaycastBackupV3(raw: Buffer): boolean {
  return raw.subarray(0, MAGIC.length).equals(MAGIC);
}

export function decodeRaycastBackupV3(raw: Buffer, password: string | null): RecordValue {
  if (!isRaycastBackupV3(raw) || raw.length < 12) throw new Error('Invalid Raycast backup header.');
  const headerSize = raw.readUInt32LE(8);
  const bodyStart = 12 + headerSize;
  if (!headerSize || headerSize > MAX_HEADER || bodyStart + 16 >= raw.length) {
    throw new Error('Invalid or truncated Raycast backup.');
  }
  const header = JSON.parse(gunzipSync(raw.subarray(12, bodyStart), { maxOutputLength: MAX_HEADER }).toString('utf8'));
  if (header.schemaVersion !== 3) throw new Error('Unsupported Raycast backup schema version.');
  const encryption = record(header.encryption);
  if (![encryption.iv, encryption.salt].every((value) => typeof value === 'string' && /^[a-f0-9]{32}$/i.test(value))) {
    throw new Error('Invalid Raycast backup encryption metadata.');
  }
  if (!password) throw new Error('A password is required to import this Raycast backup.');
  const key = scryptSync(password, Buffer.from(encryption.salt, 'hex'), 32, { N: 16384, r: 8, p: 1 });
  let compressed: Buffer;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(encryption.iv, 'hex'));
    decipher.setAuthTag(raw.subarray(-16));
    compressed = Buffer.concat([decipher.update(raw.subarray(bodyStart, -16)), decipher.final()]);
  } catch {
    throw new Error('Raycast backup password is not valid, or the encrypted backup is damaged.');
  } finally {
    key.fill(0);
  }
  const payload = JSON.parse(gunzipSync(compressed, { maxOutputLength: MAX_PAYLOAD }).toString('utf8'));
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Invalid Raycast backup payload.');
  return normalizeRaycastBackupV3(payload, header.appVersion);
}

function hotkey(value: any): string | undefined {
  const kind = record(record(value).kind);
  const shortcut = record(kind.shortcut);
  const key = record(shortcut.key);
  if (kind.type !== 'SingleStep' || key.type !== 'LayoutIndependent' || !Number.isInteger(key.code)) return undefined;
  return [...list(shortcut.modifiers).map((item) => item.modifier), key.code].join('-');
}

/** Adapt Raycast 2.x categories to the existing import pipeline. */
export function normalizeRaycastBackupV3(data: RecordValue, appVersion?: string): RecordValue {
  const settings = record(data.settings);
  const general = record(settings.general);
  const extensions = list(record(data.nodeExtensions).extensions);
  const extensionById = new Map(extensions.map((item) => [`e:n:${item.uuid}`, item]));
  const commands = list(settings.commands);
  const commandKey = (id: string): { key?: string; path?: string } => {
    const application = id.indexOf('::=::');
    if (id.startsWith('c:r:applications:') && application >= 0) return { path: id.slice(application + 5) };
    const match = /^c:n:([^:]+)::-::(.+)$/.exec(id);
    if (match) {
      const extension = extensionById.get(`e:n:${match[1]}`);
      if (extension) return { key: `extension_${extension.name}.${match[2]}` };
    }
    // Unknown built-in IDs remain visible as unmapped instead of being guessed.
    return { key: id };
  };
  const rootSearch = commands.map((item) => ({ ...commandKey(String(item.id || '')), hotkey: hotkey(item.macosHotkey), alias: item.alias }));
  const ai = record(data.ai);
  const messages = list(ai.messages);
  return {
    raycast_version: appVersion,
    builtin_package_raycastPreferences: {
      preferencesGeneral: { raycastGlobalHotkey: hotkey(general.globalHotkey) },
      preferencesAppearance: { raycastPreferredWindowMode: general.windowMode },
      preferencesAdvanced: { navigationCommandStyleIdentifierKey: general.navigationBindings, popToRootTimeout: general.popToRootTimeout },
    },
    builtin_package_rootSearch: { rootSearch },
    builtin_package_quicklinks: { quicklinks: list(record(data.quicklinks).quicklinks).map((item) => ({ ...item, uuid: item.id, url: String(item.link || '').replace(/\{query\}/gi, '{argument}') })) },
    builtin_package_snippets: { snippets: list(record(data.snippets).snippets).map((item) => ({ ...item, name: item.title || item.name })) },
    builtin_package_raycastNotes: { notes: list(record(data.notes).notes) },
    builtin_package_raycastExtensions: {
      extensions: extensions.map((extension) => {
        const extensionId = `e:n:${extension.uuid}`;
        const prefs = list(settings.nodeExtensions).find((item) => item.id === extensionId) || {};
        const values = record(prefs.meta);
        return {
          name: extension.name, owner: extension.author,
          commands: commands.filter((item) => item.extensionId === extensionId).map((item) => ({ name: String(item.id).split('::-::')[1], enabled: prefs.enabled === false ? false : item.enabled })),
          prefs: list(prefs.preferenceTypes).filter((pref) => Object.prototype.hasOwnProperty.call(values, pref.name)).map((pref) => ({ ...pref, value: values[pref.name] })),
        };
      }),
    },
    'builtin_package_open-ai': {
      aiChats: list(ai.chats).map((chat) => ({ ...chat, messages: messages.filter((message) => message.chatId === chat.id && ['user', 'assistant'].includes(message.role) && typeof message.content?.text === 'string').map((message) => ({ role: message.role, content: message.content.text, createdAt: message.createdAt })).sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt))) })),
    },
    builtin_package_clipboardHistory: { clipboardHistoryRecords: list(record(data.clipboardHistory).clipboardEntries) },
    builtin_package_mcp: { mcpServers: list(record(data.mcpServers).servers) },
  };
}
