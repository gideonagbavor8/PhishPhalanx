/* jslint es6:true, node:true */
require('dotenv').config();
const { MongoClient } = require('mongodb');

let client = null;
let dbInstance = null;

/**
 * Establish connection to MongoDB Atlas.
 */
async function connectDB() {
  if (dbInstance) return dbInstance;

  const uri = process.env.MONGO_URI;
  if (!uri) {
    throw new Error('MONGO_URI environment variable is missing.');
  }

  try {
    client = new MongoClient(uri);
    await client.connect();
    // Connects to the database specified in the URI (e.g., phishphalanx)
    dbInstance = client.db();
    return dbInstance;
  } catch (error) {
    console.error('Error connecting to MongoDB Atlas:', error);
    throw error;
  }
}

/**
 * Helper function to retrieve the initialized MongoDB database instance.
 * @returns {Promise<Object>} The database instance
 */
async function getDb() {
  if (!dbInstance) {
    await connectDB();
  }
  return dbInstance;
}

/**
 * Gracefully close the database connection.
 */
async function closeDB() {
  if (client) {
    await client.close();
    client = null;
    dbInstance = null;
  }
}

module.exports = {
  connectDB,
  getDb,
  closeDB,
};
