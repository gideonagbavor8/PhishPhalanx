/* jslint es6:true, node:true */
require('dotenv').config();
const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

let firebaseApp = null;

/**
 * Initialize Firebase Admin SDK using credentials from .env.
 * Supports either a path to a service account JSON (`FIREBASE_SERVICE_ACCOUNT_PATH`)
 * or an inlined JSON string (`FIREBASE_SERVICE_ACCOUNT`). Falls back to
 * application default credentials when neither is provided.
 */
function initializeFromEnv() {
  if (firebaseApp) return firebaseApp;

  const projectId = process.env.FIREBASE_PROJECT_ID || 'phishphalanx-demo';
  const storageBucket = process.env.FIREBASE_STORAGE_BUCKET || 'phishphalanx-storage';
  const useEmulator = (process.env.FIREBASE_USE_EMULATOR || 'true') === 'true';

  // Configure emulator endpoints when requested.
  if (useEmulator) {
    process.env.FIRESTORE_EMULATOR_HOST = process.env.FIRESTORE_EMULATOR_HOST || '127.0.0.1:8080';
    process.env.FIREBASE_STORAGE_EMULATOR_HOST = process.env.FIREBASE_STORAGE_EMULATOR_HOST || '127.0.0.1:9199';
  }

  let credential = null;

  if (process.env.FIREBASE_SERVICE_ACCOUNT_PATH) {
    const p = path.resolve(process.env.FIREBASE_SERVICE_ACCOUNT_PATH);
    if (!fs.existsSync(p)) throw new Error(`Service account file not found: ${p}`);
    credential = admin.credential.cert(require(p));
  } else if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    // Accept raw JSON string or base64-encoded JSON.
    let sa = process.env.FIREBASE_SERVICE_ACCOUNT;
    try {
      // If it looks like base64, try decoding.
      if (/^[A-Za-z0-9+/=\n]+$/.test(sa) && sa.length > 100 && sa.includes('{') === false) {
        sa = Buffer.from(sa, 'base64').toString('utf8');
      }
      const parsed = JSON.parse(sa);
      credential = admin.credential.cert(parsed);
    } catch (err) {
      throw new Error('FIREBASE_SERVICE_ACCOUNT is present but invalid JSON');
    }
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    credential = admin.credential.applicationDefault();
  }

  const initOptions = {
    projectId,
    storageBucket,
  };

  if (credential) initOptions.credential = credential;

  firebaseApp = admin.initializeApp(initOptions);

  return firebaseApp;
}

// Ensure SDK is initialized on require and export firestore instance.
initializeFromEnv();

const firestore = admin.firestore();
const storage = admin.storage();

module.exports = {
  admin,
  firestore,
  storage,
};
