/**
 * B18-T6: the device's offline store. Records, the queue of changes made
 * offline, files and sync metadata, each value encrypted with AES-GCM under
 * a non-extractable WebCrypto key that is generated once and kept in the
 * same database (never in localStorage); every value gets its own random
 * 96-bit IV. The browser's IndexedDB holds it; tests use the in-memory
 * backend.
 */

/** The four stores. */
export type StoreName = 'records' | 'queue' | 'files' | 'meta';
const STORES: readonly StoreName[] = ['records', 'queue', 'files', 'meta'];
const DB_NAME = 'attome-offline';
const KEY_ID = 'crypto-key';

/** Where values live: IndexedDB in the browser, memory in tests. */
export interface KvBackend {
  get(store: StoreName, key: string): Promise<unknown>;
  put(store: StoreName, key: string, value: unknown): Promise<void>;
  delete(store: StoreName, key: string): Promise<void>;
  keys(store: StoreName): Promise<string[]>;
  clear(): Promise<void>;
}

/** An in-memory backend: tests, and browsers without IndexedDB. */
export class MemoryBackend implements KvBackend {
  readonly data = new Map<StoreName, Map<string, unknown>>(STORES.map(s => [s, new Map()]));

  async get(store: StoreName, key: string): Promise<unknown> {
    return this.data.get(store)?.get(key);
  }

  async put(store: StoreName, key: string, value: unknown): Promise<void> {
    this.data.get(store)?.set(key, value);
  }

  async delete(store: StoreName, key: string): Promise<void> {
    this.data.get(store)?.delete(key);
  }

  async keys(store: StoreName): Promise<string[]> {
    return [...(this.data.get(store)?.keys() ?? [])];
  }

  async clear(): Promise<void> {
    this.data.forEach(m => m.clear());
  }
}

/** The browser's IndexedDB database `attome-offline`. */
export class IndexedDbBackend implements KvBackend {
  private db: Promise<IDBDatabase> | null = null;

  private open(): Promise<IDBDatabase> {
    if (!this.db) {
      this.db = new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => {
          for (const s of STORES) {
            if (!req.result.objectStoreNames.contains(s)) req.result.createObjectStore(s);
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    return this.db;
  }

  private async run<T>(store: StoreName, mode: IDBTransactionMode, act: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const req = act(db.transaction(store, mode).objectStore(store));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  get(store: StoreName, key: string): Promise<unknown> {
    return this.run(store, 'readonly', s => s.get(key));
  }

  async put(store: StoreName, key: string, value: unknown): Promise<void> {
    await this.run(store, 'readwrite', s => s.put(value, key));
  }

  async delete(store: StoreName, key: string): Promise<void> {
    await this.run(store, 'readwrite', s => s.delete(key));
  }

  async keys(store: StoreName): Promise<string[]> {
    const keys = await this.run(store, 'readonly', s => s.getAllKeys());
    return keys.map(String);
  }

  async clear(): Promise<void> {
    for (const s of STORES) await this.run(s, 'readwrite', st => st.clear());
  }
}

/** An encrypted value as stored. */
interface Sealed {
  iv: Uint8Array<ArrayBuffer>;
  data: ArrayBuffer;
}

/** A UUIDv7: time-ordered, random below the millisecond. */
export function uuidv7(now: number = Date.now()): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let ms = now;
  for (let i = 5; i >= 0; i--) {
    bytes[i] = ms % 256;
    ms = Math.floor(ms / 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export class OfflineStore {
  private key: CryptoKey | null = null;

  constructor(readonly backend: KvBackend) {}

  /** The encryption key: the stored one, or a new non-extractable one. */
  private async cryptoKey(): Promise<CryptoKey> {
    if (this.key) return this.key;
    const stored = (await this.backend.get('meta', KEY_ID)) as CryptoKey | undefined;
    this.key = stored ?? await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
    if (!stored) await this.backend.put('meta', KEY_ID, this.key);
    return this.key;
  }

  private async seal(value: unknown): Promise<Sealed> {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const data = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, await this.cryptoKey(), new TextEncoder().encode(JSON.stringify(value)),
    );
    return { iv, data };
  }

  private async open<T>(sealed: unknown): Promise<T | null> {
    if (!sealed) return null;
    const { iv, data } = sealed as Sealed;
    const plain = await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, await this.cryptoKey(), data);
    return JSON.parse(new TextDecoder().decode(plain)) as T;
  }

  async put(store: StoreName, key: string, value: unknown): Promise<void> {
    await this.backend.put(store, key, await this.seal(value));
  }

  get<T>(store: StoreName, key: string): Promise<T | null> {
    return this.backend.get(store, key).then(v => this.open<T>(v));
  }

  delete(store: StoreName, key: string): Promise<void> {
    return this.backend.delete(store, key);
  }

  async keys(store: StoreName): Promise<string[]> {
    const keys = await this.backend.keys(store);
    return store === 'meta' ? keys.filter(k => k !== KEY_ID) : keys;
  }

  /** A record's key in the `records` store. */
  static recordKey(entity: string, id: string): string {
    return `${entity}\u0000${id}`;
  }

  putRecord(entity: string, id: string, data: unknown): Promise<void> {
    return this.put('records', OfflineStore.recordKey(entity, id), data);
  }

  getRecord<T>(entity: string, id: string): Promise<T | null> {
    return this.get<T>('records', OfflineStore.recordKey(entity, id));
  }

  deleteRecord(entity: string, id: string): Promise<void> {
    return this.delete('records', OfflineStore.recordKey(entity, id));
  }

  /** Everything, the key included: a wipe leaves nothing to decrypt. */
  async wipe(): Promise<void> {
    await this.backend.clear();
    this.key = null;
  }
}
