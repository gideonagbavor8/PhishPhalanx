/* jslint es6:true, node:true */
'use strict';

/**
 * db.js — MongoDB Atlas Connection Module
 * ─────────────────────────────────────────────────────────────────────────────
 * This module is responsible for establishing and managing the single
 * Mongoose connection to our MongoDB Atlas cluster. All other modules
 * (incidents.js, blacklist.js, seed.js) import connectDB() from here
 * to ensure only one shared connection is used across the entire app.
 * ─────────────────────────────────────────────────────────────────────────────
 */

// Step 1: Load environment variables from the .env file into process.env.
// This must be called before reading any process.env.* values so that
// MONGODB_URI is available when connectDB() runs.
require('dotenv').config();

// Step 2: Import Mongoose — the ODM (Object Data Modelling) library that
// wraps the native MongoDB driver and adds schemas, models, and validation.
const mongoose = require('mongoose');

/**
 * connectDB()
 * ─────────────────────────────────────────────────────────────────────────────
 * Establishes a connection to MongoDB Atlas using the Mongoose ODM.
 *
 * How it works:
 *  1. Checks if Mongoose is already connected (readyState === 1) to avoid
 *     opening duplicate connections — Mongoose manages a single pool.
 *  2. Reads the MONGODB_URI connection string from the .env file.
 *  3. Calls mongoose.connect() which opens the connection pool to Atlas.
 *  4. Returns the active connection object so callers can confirm success.
 *  5. If anything fails, the error is logged and re-thrown so the calling
 *     code can handle it (e.g., exit the process or show an error message).
 *
 * @returns {Promise<mongoose.Connection>} The active Mongoose connection
 * @throws  {Error} If MONGODB_URI is missing or the Atlas cluster is unreachable
 */
async function connectDB() {
  // Step 3: Guard — if Mongoose is already connected (readyState 1 = connected),
  // return the existing connection immediately without reconnecting.
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  // Step 4: Read the MongoDB Atlas connection string from the environment.
  // The variable is named MONGODB_URI and must be defined in the .env file.
  // Format: mongodb+srv://<user>:<password>@<cluster>.mongodb.net/<dbName>
  const uri = process.env.MONGODB_URI;

  // Step 5: Validate that the URI was actually loaded. If the .env file is
  // missing or the variable is misspelled, we fail fast with a clear message
  // instead of getting a cryptic Mongoose connection error.
  if (!uri) {
    throw new Error(
      '❌ MONGODB_URI is not defined. Please add it to your .env file.\n' +
      '   Example: MONGODB_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/phishphalanx'
    );
  }

  try {
    // Step 6: Connect to MongoDB Atlas. Mongoose uses the URI to determine
    // the host, port, authentication credentials, and database name.
    // The connection pool is managed internally by Mongoose — we don't need
    // to open or close individual connections for each query.
    await mongoose.connect(uri);

    // Step 7: Log confirmation so we know the connection succeeded at runtime.
    console.log('✅ Connected to MongoDB Atlas via Mongoose');

    // Step 8: Return the active connection object for callers that need it.
    return mongoose.connection;

  } catch (error) {
    // Step 9: If the connection attempt fails (wrong password, network issue,
    // cluster paused, etc.), log the specific error message and re-throw it
    // so the caller can decide how to respond (exit, retry, alert, etc.).
    console.error('❌ MongoDB Atlas connection failed:', error.message);
    throw error;
  }
}

/**
 * closeDB()
 * ─────────────────────────────────────────────────────────────────────────────
 * Gracefully closes the Mongoose connection to MongoDB Atlas.
 *
 * This is important in CLI apps: without explicitly closing the connection,
 * Node.js keeps the event loop alive and the process never exits on its own.
 * We call closeDB() in the `finally` block of every CLI command handler.
 *
 * @returns {Promise<void>}
 */
async function closeDB() {
  // readyState 0 means already disconnected — nothing to close.
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
    console.log('🔌 MongoDB connection closed.');
  }
}

// Step 10: Export both functions so other modules can import them.
// - connectDB  → called at the start of every CLI command
// - closeDB    → called in the finally block to clean up after every command
module.exports = {
  connectDB,
  closeDB,
};
