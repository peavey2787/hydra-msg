const DB_NAME = 'hydra-gui-message-view';
const DB_VERSION = 1;
const STORE_NAME = 'messages';
const MAX_PER_CONVERSATION = 500;

export class MessageViewStore {
  constructor() {
    this.dbPromise = undefined;
    this.tail = Promise.resolve();
    this.sequence = 0;
  }

  async load(scope) {
    const records = await this.allRecords();
    return records
      .filter(record => record.scope === scope)
      .sort((left, right) => left.order - right.order)
      .map(record => ({ conversationKey: record.conversationKey, message: record.message }));
  }

  put(scope, conversationKey, message) {
    return this.enqueue(async () => {
      const db = await this.open();
      const key = recordKey(scope, conversationKey, message.messageKey);
      const prior = await request(db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(key));
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      transaction.objectStore(STORE_NAME).put({
        key,
        scope,
        conversationKey,
        messageKey: String(message.messageKey),
        order: prior?.order ?? nextOrder(this),
        message: persistedMessage(message),
      });
      await transactionDone(transaction);
      await this.trim(scope, conversationKey);
    });
  }

  delete(scope, conversationKey, messageKey) {
    return this.enqueue(async () => {
      const db = await this.open();
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      transaction.objectStore(STORE_NAME).delete(recordKey(scope, conversationKey, messageKey));
      await transactionDone(transaction);
    });
  }

  clearConversation(scope, conversationKey) {
    return this.enqueue(async () => {
      const records = (await this.allRecords())
        .filter(record => record.scope === scope && record.conversationKey === conversationKey);
      if (!records.length) return;
      const db = await this.open();
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      for (const record of records) store.delete(record.key);
      await transactionDone(transaction);
    });
  }

  enqueue(task) {
    const run = this.tail.then(task, task);
    this.tail = run.catch(() => undefined);
    return run;
  }

  open() {
    this.dbPromise ??= new Promise((resolve, reject) => {
      const opening = indexedDB.open(DB_NAME, DB_VERSION);
      opening.onupgradeneeded = () => {
        if (!opening.result.objectStoreNames.contains(STORE_NAME)) {
          opening.result.createObjectStore(STORE_NAME, { keyPath: 'key' });
        }
      };
      opening.onsuccess = () => resolve(opening.result);
      opening.onerror = () => reject(opening.error ?? new Error('Could not open GUI message-view storage.'));
    });
    return this.dbPromise;
  }

  async allRecords() {
    const db = await this.open();
    return request(db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).getAll());
  }

  async trim(scope, conversationKey) {
    const records = (await this.allRecords())
      .filter(record => record.scope === scope && record.conversationKey === conversationKey)
      .sort((left, right) => left.order - right.order);
    const excess = records.length - MAX_PER_CONVERSATION;
    if (excess <= 0) return;
    const db = await this.open();
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    for (const record of records.slice(0, excess)) store.delete(record.key);
    await transactionDone(transaction);
  }
}

function persistedMessage(message) {
  const copy = { ...message };
  delete copy.privacyRevealed;
  delete copy.stegoView;
  delete copy.carrierScrollTop;
  delete copy.removalRequest;
  return copy;
}

function recordKey(scope, conversationKey, messageKey) {
  return `${scope}|${conversationKey}|${messageKey}`;
}

function nextOrder(store) {
  store.sequence = (store.sequence + 1) % 1000;
  return Date.now() * 1000 + store.sequence;
}

function request(value) {
  return new Promise((resolve, reject) => {
    value.onsuccess = () => resolve(value.result);
    value.onerror = () => reject(value.error ?? new Error('GUI message-view storage failed.'));
  });
}

function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error('GUI message-view transaction was aborted.'));
    transaction.onerror = () => reject(transaction.error ?? new Error('GUI message-view transaction failed.'));
  });
}
