/* jslint es6:true, node:true */
/**
 * Firebase Admin initialization helper for PhishPhalanx.
 * Supports Firebase Emulator Suite for local development and live Firebase projects.
 */
const admin = require('firebase-admin');
const path = require('path');

let firebaseApp = null;

/**
 * Initialize Firebase Admin for Firestore and Storage.
 * @param {Object} options
 * @param {string} [options.projectId='phishphalanx-demo']
 * @param {string} [options.storageBucket='phishphalanx-storage']
 * @param {string} [options.serviceAccountPath] - path to service account JSON for production.
 * @param {boolean} [options.useEmulator=true] - connect to local emulator by default.
 * @param {string} [options.emulatorHost='127.0.0.1']
 * @param {number} [options.emulatorFirestorePort=8080]
 * @param {number} [options.emulatorStoragePort=9199]
 * @returns {{app:Object, firestore:Object, storage:Object}}
 */
function initializeFirebase(options = {}) {
  const {
    projectId = 'phishphalanx-demo',
    storageBucket = 'phishphalanx-storage',
    serviceAccountPath,
    useEmulator = true,
    emulatorHost = '127.0.0.1',
    emulatorFirestorePort = 8080,
    emulatorStoragePort = 9199,
  } = options;

  if (firebaseApp) {
    return {
      app: firebaseApp,
      firestore: admin.firestore(),
      storage: admin.storage(),
    };
  }

  if (useEmulator) {
    process.env.FIRESTORE_EMULATOR_HOST = `${emulatorHost}:${emulatorFirestorePort}`;
    process.env.FIREBASE_STORAGE_EMULATOR_HOST = `${emulatorHost}:${emulatorStoragePort}`;
  }

  const initOptions = {
    projectId,
    storageBucket,
  };

  if (serviceAccountPath) {
    initOptions.credential = admin.credential.cert(path.resolve(serviceAccountPath));
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    initOptions.credential = admin.credential.applicationDefault();
  }

  firebaseApp = admin.initializeApp(initOptions);

  return {
    app: firebaseApp,
    firestore: admin.firestore(),
    storage: admin.storage(),
  };
}

module.exports = {
  initializeFirebase,
};
