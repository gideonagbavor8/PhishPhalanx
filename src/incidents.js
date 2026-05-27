/* jslint es6:true, node:true */
const crypto = require('crypto');
const { getDb } = require('./db');

const INCIDENTS_COLLECTION = 'incidents';

/**
 * Creates a new incident document in the MongoDB collection.
 */
async function createIncident({ analystId, clientIp, dangerLevel }) {
  const db = await getDb();
  // Generate a random 8-character ID for the incident (e.g., INC-A1B2C3D4)
  const incidentId = `INC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const now = new Date();

  const doc = {
    incident_id: incidentId,
    timestamp: now,
    danger_level: dangerLevel || 'low',
    status: 'unresolved',
    reporter_metadata: {
      analyst_id: analystId,
      client_ip: clientIp || '0.0.0.0',
    },
  };

  await db.collection(INCIDENTS_COLLECTION).insertOne(doc);
  return doc;
}

/**
 * Retrieve incidents from the collection, optionally filtering by status or danger level.
 */
async function listIncidents(filters = {}) {
  const db = await getDb();
  const query = {};
  
  if (filters.status) query.status = filters.status;
  if (filters.dangerLevel) query.danger_level = filters.dangerLevel;

  // Find and sort by newest first
  const results = await db.collection(INCIDENTS_COLLECTION)
    .find(query)
    .sort({ timestamp: -1 })
    .toArray();
    
  return results;
}

/**
 * Updates the resolution status of an incident.
 */
async function updateIncidentStatus(incidentId, newStatus) {
  const db = await getDb();
  const validStatuses = ['unresolved', 'investigating', 'resolved'];
  
  if (!validStatuses.includes(newStatus)) {
    throw new Error(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
  }

  const result = await db.collection(INCIDENTS_COLLECTION).updateOne(
    { incident_id: incidentId },
    { $set: { status: newStatus } }
  );

  if (result.matchedCount === 0) {
    throw new Error(`Incident ${incidentId} not found`);
  }
  return true;
}

module.exports = {
  createIncident,
  listIncidents,
  updateIncidentStatus,
};
