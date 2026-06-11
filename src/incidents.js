/* jslint es6:true, node:true */
'use strict';

/**
 * incidents.js — CRUD Operations for Phishing Incidents
 * ─────────────────────────────────────────────────────────────────────────────
 * Provides the business logic layer for creating, reading, and updating
 * phishing incident records using the native MongoDB driver instead of Mongoose.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const crypto = require('crypto');
const db = require('./db');

// ── CRUD Operations ────────────────────────────────────────────────────────────

/**
 * createIncident()
 * Creates and persists a new phishing incident document in MongoDB Atlas.
 *
 * @param {{ reporterEmail?: string, dangerLevel?: string, targetDomain: string }} params
 * @returns {Promise<Object>} The saved incident as a plain JS object
 * @throws {Error} If validation fails or database operation fails
 */
async function createIncident({ reporterEmail, dangerLevel, targetDomain } = {}) {
  try {
    // Validation checks to maintain data integrity
    if (!targetDomain) {
      throw new Error('targetDomain is required — every incident must have a target.');
    }

    const validLevels = ['low', 'medium', 'high'];
    const finalDangerLevel = dangerLevel || 'low';
    if (!validLevels.includes(finalDangerLevel)) {
      throw new Error('dangerLevel must be one of: low, medium, high');
    }

    // Auto-generate incident ID (e.g., INC-3F9A12BC) using 4 random bytes
    const incidentId = `INC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const now = new Date();

    const doc = {
      incidentId,
      targetDomain: targetDomain.trim(),
      dangerLevel: finalDangerLevel,
      reporterEmail: reporterEmail ? reporterEmail.trim() : '',
      status: 'open',
      timestamp: now,
    };

    // The MongoDB driver's collection('incidents').insertOne() method inserts a single
    // document into the collection. It modifies the document object in-place by adding
    // a unique '_id' field before sending it to Atlas.
    await db.collection('incidents').insertOne(doc);

    console.log(`✅ Incident created successfully: ${doc.incidentId}`);
    return doc;
  } catch (error) {
    console.error('❌ Failed to create incident:', error.message);
    throw error;
  }
}

/**
 * listIncidents()
 * Retrieves incidents from MongoDB, with optional filtering.
 *
 * @param {{ status?: string, dangerLevel?: string }} filters
 * @returns {Promise<Array>} Array of incident documents (plain objects)
 * @throws {Error} If database query fails
 */
async function listIncidents(filters = {}) {
  try {
    const query = {};
    if (filters.status)      query.status      = filters.status;
    if (filters.dangerLevel) query.dangerLevel  = filters.dangerLevel;

    // The MongoDB driver's collection('incidents').find(query) method returns a cursor
    // for documents matching the query. We sort the cursor in descending order by
    // timestamp (-1) and call toArray() to asynchronously fetch all documents as an array.
    const incidents = await db.collection('incidents')
      .find(query)
      .sort({ timestamp: -1 })
      .toArray();

    console.log(`✅ Retrieved ${incidents.length} incident(s) with filters:`, filters);
    return incidents;
  } catch (error) {
    console.error('❌ Failed to list incidents:', error.message);
    throw error;
  }
}

/**
 * getIncident()
 * Finds a single incident by its unique incidentId.
 *
 * @param {string} incidentId  The unique INC-XXXXXXXX identifier
 * @returns {Promise<Object|null>} The incident document or null if not found
 * @throws {Error} If database query fails
 */
async function getIncident(incidentId) {
  try {
    if (!incidentId || typeof incidentId !== 'string') {
      throw new Error('Invalid incidentId provided. Must be a non-empty string.');
    }

    // The MongoDB driver's collection('incidents').findOne(query) method finds and returns the
    // first document in the collection that matches the query filter. If no matching document
    // is found, it returns null.
    const incident = await db.collection('incidents').findOne({ incidentId });
    
    if (!incident) {
      console.warn(`⚠️  Incident "${incidentId}" not found.`);
      return null;
    }

    console.log(`✅ Retrieved incident: ${incidentId}`);
    return incident;
  } catch (error) {
    console.error('❌ Failed to retrieve incident:', error.message);
    throw error;
  }
}

/**
 * updateIncidentStatus()
 * Updates the workflow status of a specific incident by its incidentId.
 *
 * @param {string} incidentId  The unique INC-XXXXXXXX identifier
 * @param {string} newStatus   Must be one of: open, investigating, closed
 * @returns {Promise<boolean>} true if update succeeded
 * @throws {Error} If the status is invalid or the incident is not found
 */
async function updateIncidentStatus(incidentId, newStatus) {
  try {
    if (!incidentId || typeof incidentId !== 'string') {
      throw new Error('Invalid incidentId provided. Must be a non-empty string.');
    }

    const validStatuses = ['open', 'investigating', 'closed'];
    if (!validStatuses.includes(newStatus)) {
      throw new Error(`Invalid status "${newStatus}". Must be one of: ${validStatuses.join(', ')}`);
    }

    // The MongoDB driver's collection('incidents').updateOne(filter, update) method updates
    // a single document matching the filter query. We use the $set operator to change
    // the status field. It returns an object containing matchedCount and modifiedCount.
    const result = await db.collection('incidents').updateOne(
      { incidentId },
      { $set: { status: newStatus } }
    );

    if (result.matchedCount === 0) {
      throw new Error(`Incident "${incidentId}" not found.`);
    }

    console.log(`✅ Updated incident ${incidentId} status to "${newStatus}"`);
    return true;
  } catch (error) {
    console.error('❌ Failed to update incident status:', error.message);
    throw error;
  }
}

/**
 * deleteIncident()
 * Removes a false positive or incorrectly flagged incident from the database.
 *
 * @param {string} incidentId  The unique INC-XXXXXXXX identifier
 * @returns {Promise<boolean>} true if deletion succeeded
 * @throws {Error} If the incident is not found or deletion fails
 */
async function deleteIncident(incidentId) {
  try {
    if (!incidentId || typeof incidentId !== 'string') {
      throw new Error('Invalid incidentId provided. Must be a non-empty string.');
    }

    // The MongoDB driver's collection('incidents').deleteOne(filter) method deletes
    // a single document matching the filter query. It returns an object containing deletedCount.
    const result = await db.collection('incidents').deleteOne({ incidentId });

    if (result.deletedCount === 0) {
      throw new Error(`Incident "${incidentId}" not found. Nothing was deleted.`);
    }

    console.log(`✅ Deleted incident: ${incidentId}`);
    return true;
  } catch (error) {
    console.error('❌ Failed to delete incident:', error.message);
    throw error;
  }
}

/**
 * getIncidentsBySeverity()
 * Queries all OPEN incidents matching a specific danger level.
 *
 * @param {string} level  Must be one of: low, medium, high
 * @returns {Promise<Array>} Array of open incident documents sorted by newest first
 * @throws {Error} If the severity level is invalid or database query fails
 */
async function getIncidentsBySeverity(level) {
  try {
    const validLevels = ['low', 'medium', 'high'];
    if (!validLevels.includes(level)) {
      throw new Error(`Invalid severity level "${level}". Must be one of: ${validLevels.join(', ')}`);
    }

    // The MongoDB driver's collection('incidents').find(query) method is called here with a
    // compound query filter object { dangerLevel: level, status: 'open' } to find all open
    // incidents matching the specified severity level. We sort by timestamp descending (-1)
    // and convert the cursor to an array using toArray().
    const incidents = await db.collection('incidents').find({ 
      dangerLevel: level,
      status: 'open'
    }).sort({ timestamp: -1 }).toArray();

    console.log(`✅ Retrieved ${incidents.length} open incident(s) at severity level "${level}"`);
    return incidents;
  } catch (error) {
    console.error('❌ Failed to retrieve incidents by severity:', error.message);
    throw error;
  }
}

module.exports = {
  createIncident,
  listIncidents,
  updateIncidentStatus,
  getIncident,
  getIncidentsBySeverity,
  deleteIncident,
};
