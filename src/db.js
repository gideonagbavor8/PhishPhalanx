/* jslint es6:true, node:true */
'use strict';

/**
 * db.js - Native MongoDB Atlas Connection Module
 * ---------------------------------------------------------------------------
 * This module creates one shared MongoDB client for the whole application using
 * the official MongoDB Node.js driver. Mongoose is intentionally not used here:
 * callers receive the native MongoDB `Db` instance and can work with native
 * collections by calling `db.collection('collectionName')`.
 *
 * The module exports the database instance directly:
 *
 *   const db = require('./db');
 *   const incidents = db.collection('incidents');
 *
 * To keep the current CLI entry points working while other modules migrate to
 * native-driver collection calls, the exported `db` object also has connectDB()
 * and closeDB() helper properties attached to it.
 * ---------------------------------------------------------------------------
 */

// Step 1: Load variables from the project's .env file into process.env.
// This must happen before we read MONGODB_URI so local development, scripts,
// and CLI commands all use the same Atlas connection string.
require('dotenv').config();

// Step 2: Import MongoClient from the official native MongoDB driver.
// MongoClient owns the socket pool, authentication state, monitoring, retries,
// and all low-level communication with MongoDB Atlas.
const { MongoClient } = require('mongodb');

// Step 3: Read the Atlas connection string from the environment.
// The .env file should contain a value like:
// MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/<database>
const uri = process.env.MONGODB_URI;

// Step 4: Fail fast with a clear configuration error if the URI is missing.
// Without this value the native driver cannot know which Atlas cluster or
// database to connect to, and later query errors would be much harder to read.
if (!uri) {
  throw new Error(
    'MONGODB_URI is not defined. Add it to your .env file, for example: ' +
    'MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/phishphalanx'
  );
}

// Step 5: Create a single MongoClient instance for the entire Node.js process.
// Reusing one client lets the driver reuse one managed connection pool instead
// of opening new network connections for every database operation.
const client = new MongoClient(uri);

// Step 6: Create the native Db instance from the client.
// Calling client.db() with no argument tells the driver to use the database name
// embedded in MONGODB_URI. For example, a URI ending in "/phishphalanx" produces
// a Db instance for the "phishphalanx" database.
const db = client.db();

// Step 7: Track the in-flight connection promise so repeated connectDB() calls
// share the same connection attempt. This prevents duplicate simultaneous calls
// from racing each other during startup.
let connectionPromise = null;

// Step 8: Track whether this module has completed an explicit connection.
// Native collection operations can auto-connect, but the CLI calls connectDB()
// deliberately so startup can report connection errors before showing the menu.
let isConnected = false;

/**
 * connectDB()
 * ---------------------------------------------------------------------------
 * Opens the MongoDB Atlas connection pool with the native driver.
 *
 * How it works:
 *  1. If we already connected successfully, return the exported Db instance.
 *  2. If another caller is already connecting, await that same promise.
 *  3. Otherwise call client.connect(), which authenticates with Atlas and
 *     initializes the driver's connection pool.
 *  4. Return the native Db instance so callers can use collections directly.
 *
 * @returns {Promise<import('mongodb').Db>} Shared native MongoDB database
 */
async function connectDB() {
  // Step 9: If the explicit connection already succeeded, immediately return
  // the same Db object exported by this module.
  if (isConnected) {
    return db;
  }

  // Step 10: Start exactly one connection attempt. If connectDB() is called
  // again before the first attempt finishes, both callers await this promise.
  if (!connectionPromise) {
    connectionPromise = client.connect()
      .then(() => {
        // Step 11: Mark the connection as ready only after client.connect()
        // resolves. At this point Atlas authentication and server selection
        // have succeeded.
        isConnected = true;
        console.log('Connected to MongoDB Atlas using the native MongoDB driver.');
        return db;
      })
      .catch((error) => {
        // Step 12: Clear the cached promise after a failed attempt so a later
        // call can retry instead of reusing a permanently rejected promise.
        connectionPromise = null;
        console.error('MongoDB Atlas connection failed:', error.message);
        throw error;
      });
  }

  // Step 13: Return the shared promise, which resolves to the shared Db object.
  return connectionPromise;
}

/**
 * closeDB()
 * ---------------------------------------------------------------------------
 * Closes the native MongoDB client and its connection pool.
 *
 * This is useful for CLI scripts because an open MongoDB client keeps Node's
 * event loop alive. Closing the client allows commands and seed scripts to exit
 * cleanly after their database work is done.
 *
 * @returns {Promise<void>}
 */
async function closeDB() {
  // Step 14: client.close() is safe to call even if the client never connected.
  // It shuts down sockets, monitoring timers, and pooled connections owned by
  // this MongoClient instance.
  await client.close();

  // Step 15: Reset our local state so a long-running process can reconnect
  // later by calling connectDB() again.
  connectionPromise = null;
  isConnected = false;

  console.log('MongoDB connection closed.');
}

// Step 16: Attach helper functions to the native Db object. This keeps existing
// code such as `const { connectDB, closeDB } = require('./db')` working while
// still making the module's primary export the database instance itself.
db.connectDB = connectDB;
db.closeDB = closeDB;

// Step 17: Add short aliases for modules that prefer method-like names on the
// exported database object: `await db.connect()` and `await db.close()`.
db.connect = connectDB;
db.close = closeDB;

// Step 18: Export the database instance directly for use in other modules.
module.exports = db;
