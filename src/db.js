/* jslint es6:true, node:true */
'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

/**
 * Establish a Mongoose connection to MongoDB Atlas.
 * Mongoose manages the connection pool internally.
 */
async function connectDB() {
  if (mongoose.connection.readyState === 1) {
    // Already connected
    return mongoose.connection;
  }

  const uri = process.env.MONGO_URI;
  if (!uri) {
    throw new Error('MONGO_URI environment variable is missing.');
  }

  try {
    await mongoose.connect(uri);
    console.log('✅ Connected to MongoDB Atlas via Mongoose');
    return mongoose.connection;
  } catch (error) {
    console.error('❌ Error connecting to MongoDB Atlas:', error.message);
    throw error;
  }
}

/**
 * Gracefully close the Mongoose connection.
 */
async function closeDB() {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
    console.log('🔌 MongoDB connection closed.');
  }
}

module.exports = {
  connectDB,
  closeDB,
};
