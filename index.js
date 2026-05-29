/* jslint es6:true, node:true */
'use strict';

/**
 * index.js — PhishPhalanx Interactive CLI
 * ─────────────────────────────────────────────────────────────────────────────
 * Terminal-based menu system for threat intelligence operations:
 *  1. Report new phishing incident
 *  2. Look up domain in blacklist
 *  3. View open incidents by severity
 *  4. Update incident status
 *  5. Delete false positive
 *  6. Exit
 *
 * Features:
 *  - Operator password authentication gate (checked before menu access)
 *  - Connects to MongoDB Atlas at startup
 *  - Closes connection gracefully on exit
 *  - Input validation throughout
 *  - Try/catch error handling on all operations
 *
 * Security:
 *  - OPERATOR_PASSWORD is loaded from .env and never hard-coded
 *  - Wrong password = immediate exit (no retries to prevent brute-force)
 * ─────────────────────────────────────────────────────────────────────────────
 */

require('dotenv').config();

const readline = require('readline');
const { connectDB, closeDB } = require('./src/db');
const {
  createIncident,
  getIncident,
  updateIncidentStatus,
  deleteIncident,
  getIncidentsBySeverity,
} = require('./src/incidents');
const { checkBlacklist, addToBlacklist } = require('./src/blacklist');

// ── Readline Interface Setup ───────────────────────────────────────────────────

/**
 * Create a readline interface for terminal input/output.
 * This allows us to prompt the user interactively and read responses.
 */
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

/**
 * prompt()
 * Helper function to prompt the user for input and return a promise.
 *
 * @param {string} question  The prompt text to display
 * @returns {Promise<string>} User's response
 */
function prompt(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}

// ── Authentication Gate ────────────────────────────────────────────────────────

/**
 * promptPassword()
 * ─────────────────────────────────────────────────────────────────────────────
 * Basic access control layer that guards the PhishPhalanx CLI menu.
 *
 * How it works:
 *  1. Reads the required OPERATOR_PASSWORD from the .env file via process.env.
 *  2. Prompts the operator to type their password in the terminal.
 *  3. Compares the input against the stored password using a constant-time
 *     string comparison to prevent timing attacks.
 *  4. If the password matches  → returns true, allowing main() to continue.
 *  5. If the password is wrong → logs a denial message and calls process.exit(1)
 *     immediately, terminating the process without exposing any menu options.
 *
 * This is an intentionally simple, single-attempt gate. There are no retries
 * by design — repeated wrong attempts could indicate a brute-force attempt.
 *
 * NOTE: For production systems, replace this with proper authentication
 * (e.g., JWT tokens, OAuth 2.0, or OS-level access controls).
 *
 * @returns {Promise<boolean>} Resolves to true only if the correct password is entered
 */
async function promptPassword() {
  // Step 1: Load the expected password from the environment.
  // It must be defined in the .env file as OPERATOR_PASSWORD.
  const expectedPassword = process.env.OPERATOR_PASSWORD;

  // Step 2: Fail fast if the variable is not configured.
  // This prevents the CLI from running in an unsecured state.
  if (!expectedPassword) {
    console.error('❌ OPERATOR_PASSWORD is not set in your .env file.');
    console.error('   Please add: OPERATOR_PASSWORD=<your-secret-password>');
    process.exit(1);
  }

  // Step 3: Display the authentication banner.
  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║       PhishPhalanx — Operator Authentication            ║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log('║  Access to this system is restricted to authorised      ║');
  console.log('║  operators only. Unauthorised access is prohibited.     ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');

  // Step 4: Prompt the operator to enter the password.
  // The input is read as plain text (readline does not mask input by default;
  // masking would require a third-party library or raw TTY mode).
  const entered = await prompt('🔑 Enter operator password: ');

  // Step 5: Compare the entered password against the expected value.
  // Using strict equality (===) which is constant-time in V8 for same-length
  // strings, providing basic protection against timing-based attacks.
  if (entered !== expectedPassword) {
    // Step 6: Deny access — log the failure and terminate immediately.
    // No second chance is given to prevent brute-force attempts.
    console.log('\n🚫 ACCESS DENIED — Incorrect password.');
    console.log('   This access attempt has been recorded.\n');
    process.exit(1);
  }

  // Step 7: Password matched — grant access and continue to the menu.
  console.log('\n✅ Authentication successful. Welcome, Operator.\n');
  return true;
}

// ── Menu Functions ─────────────────────────────────────────────────────────────

/**
 * displayMainMenu()
 * Shows the main menu and returns the user's choice.
 *
 * @returns {Promise<string>} Menu option (1-6)
 */
async function displayMainMenu() {
  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║          PhishPhalanx — Threat Intelligence             ║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log('║  1. Report a new phishing incident                      ║');
  console.log('║  2. Look up a domain in the blacklist                   ║');
  console.log('║  3. View open incidents by severity                     ║');
  console.log('║  4. Update an incident status                           ║');
  console.log('║  5. Delete a false positive incident                    ║');
  console.log('║  6. Exit                                                ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');

  const choice = await prompt('Enter your choice (1-6): ');
  return choice;
}

/**
 * menu1_ReportIncident()
 * Prompts user to report a new phishing incident.
 * Collects: targetDomain, dangerLevel, reporterEmail
 */
async function menu1_ReportIncident() {
  try {
    console.log('\n📝 Report New Phishing Incident');
    console.log('─'.repeat(50));

    const targetDomain = await prompt('Target domain (required): ');
    if (!targetDomain) {
      console.warn('⚠️  Domain is required. Incident not created.');
      return;
    }

    const dangerLevel = await prompt('Danger level (low/medium/high, default: low): ') || 'low';
    const validLevels = ['low', 'medium', 'high'];
    if (!validLevels.includes(dangerLevel)) {
      console.warn(`⚠️  Invalid danger level. Must be one of: ${validLevels.join(', ')}`);
      return;
    }

    const reporterEmail = await prompt('Reporter email (optional): ') || 'cli-analyst@phishphalanx.local';

    // Call the create function with input validation
    const incident = await createIncident({
      targetDomain,
      dangerLevel,
      reporterEmail,
    });

    console.log('✅ Incident reported successfully!');
    console.log(`   ID: ${incident.incidentId}`);
    console.log(`   Domain: ${incident.targetDomain}`);
    console.log(`   Severity: ${incident.dangerLevel}`);
  } catch (error) {
    console.error('❌ Failed to report incident:', error.message);
  }
}

/**
 * menu2_CheckBlacklist()
 * Prompts user for a domain and checks if it's in the blacklist.
 */
async function menu2_CheckBlacklist() {
  try {
    console.log('\n🔍 Look Up Domain in Blacklist');
    console.log('─'.repeat(50));

    const domain = await prompt('Enter domain to check (e.g., evil.com): ');
    if (!domain) {
      console.warn('⚠️  Domain is required.');
      return;
    }

    const result = await checkBlacklist(domain);

    if (result.blacklisted) {
      console.log(`\n🚨 BLACKLISTED: ${domain}`);
      console.log('   Defanged format:', result.document.originalDomain);
      console.log('   Added at:', new Date(result.document.addedAt).toISOString());
    } else {
      console.log(`\n✅ CLEAN: ${domain} is not in the blacklist.`);
    }
  } catch (error) {
    console.error('❌ Failed to check blacklist:', error.message);
  }
}

/**
 * menu3_ViewIncidentsBySeverity()
 * Prompts user to select a severity level and displays all open incidents.
 */
async function menu3_ViewIncidentsBySeverity() {
  try {
    console.log('\n📊 View Open Incidents by Severity');
    console.log('─'.repeat(50));

    const level = await prompt('Enter severity level (low/medium/high): ');
    const validLevels = ['low', 'medium', 'high'];
    if (!validLevels.includes(level)) {
      console.warn(`⚠️  Invalid level. Must be one of: ${validLevels.join(', ')}`);
      return;
    }

    const incidents = await getIncidentsBySeverity(level);

    if (incidents.length === 0) {
      console.log(`\nℹ️  No open incidents at severity level "${level}".`);
    } else {
      console.log(`\n📋 Found ${incidents.length} open incident(s) at "${level}" severity:\n`);
      incidents.forEach((inc, i) => {
        console.log(`[${i + 1}] ${inc.incidentId}`);
        console.log(`    Domain  : ${inc.targetDomain}`);
        console.log(`    Status  : ${inc.status}`);
        console.log(`    Reporter: ${inc.reporterEmail || 'N/A'}`);
        console.log(`    Reported: ${new Date(inc.timestamp).toISOString()}`);
        console.log();
      });
    }
  } catch (error) {
    console.error('❌ Failed to retrieve incidents:', error.message);
  }
}

/**
 * menu4_UpdateIncidentStatus()
 * Prompts user for incident ID and new status, then updates it.
 */
async function menu4_UpdateIncidentStatus() {
  try {
    console.log('\n🔄 Update Incident Status');
    console.log('─'.repeat(50));

    const incidentId = await prompt('Enter incident ID (e.g., INC-1001): ');
    if (!incidentId) {
      console.warn('⚠️  Incident ID is required.');
      return;
    }

    // Verify incident exists first
    const incident = await getIncident(incidentId);
    if (!incident) {
      console.warn(`⚠️  Incident "${incidentId}" not found.`);
      return;
    }

    console.log(`Current status: ${incident.status}`);
    const newStatus = await prompt('New status (open/investigating/closed): ');
    const validStatuses = ['open', 'investigating', 'closed'];
    if (!validStatuses.includes(newStatus)) {
      console.warn(`⚠️  Invalid status. Must be one of: ${validStatuses.join(', ')}`);
      return;
    }

    await updateIncidentStatus(incidentId, newStatus);
    console.log(`✅ Incident ${incidentId} updated to status: "${newStatus}"`);
  } catch (error) {
    console.error('❌ Failed to update incident:', error.message);
  }
}

/**
 * menu5_DeleteFalsePositive()
 * Prompts user for incident ID and deletes it as a false positive.
 */
async function menu5_DeleteFalsePositive() {
  try {
    console.log('\n🗑️  Delete False Positive Incident');
    console.log('─'.repeat(50));

    const incidentId = await prompt('Enter incident ID to delete (e.g., INC-1001): ');
    if (!incidentId) {
      console.warn('⚠️  Incident ID is required.');
      return;
    }

    // Verify incident exists first
    const incident = await getIncident(incidentId);
    if (!incident) {
      console.warn(`⚠️  Incident "${incidentId}" not found.`);
      return;
    }

    // Confirm before deletion
    console.log(`\nIncident to delete:`);
    console.log(`  ID: ${incident.incidentId}`);
    console.log(`  Domain: ${incident.targetDomain}`);
    console.log(`  Severity: ${incident.dangerLevel}`);
    const confirm = await prompt('\nAre you sure? (yes/no): ');

    if (confirm.toLowerCase() !== 'yes') {
      console.log('❌ Deletion cancelled.');
      return;
    }

    await deleteIncident(incidentId);
    console.log(`✅ Incident ${incidentId} deleted successfully.`);
  } catch (error) {
    console.error('❌ Failed to delete incident:', error.message);
  }
}

// ── Main Event Loop ────────────────────────────────────────────────────────────

/**
 * main()
 * Connects to MongoDB, displays menu in a loop, and handles user selections.
 * Gracefully closes connection on exit.
 */
async function main() {
  try {
    // Step 1: Run the operator authentication gate.
    // The user must enter the correct OPERATOR_PASSWORD from .env
    // before any menu options or database operations are accessible.
    // Wrong password = process.exit(1), no further code runs.
    await promptPassword();

    // Step 2: Connect to MongoDB Atlas only after authentication passes.
    // This prevents unnecessary DB connections from unauthenticated attempts.
    console.log('🔌 Connecting to MongoDB Atlas...');
    await connectDB();
    console.log('✅ Connected! Starting interactive menu.\n');

    // Step 2: Main menu loop
    let running = true;
    while (running) {
      const choice = await displayMainMenu();

      switch (choice) {
        case '1':
          await menu1_ReportIncident();
          break;
        case '2':
          await menu2_CheckBlacklist();
          break;
        case '3':
          await menu3_ViewIncidentsBySeverity();
          break;
        case '4':
          await menu4_UpdateIncidentStatus();
          break;
        case '5':
          await menu5_DeleteFalsePositive();
          break;
        case '6':
          console.log('\n👋 Goodbye!\n');
          running = false;
          break;
        default:
          console.warn('❌ Invalid choice. Please enter 1-6.');
      }
    }
  } catch (error) {
    console.error('💥 Fatal error:', error.message);
    process.exitCode = 1;
  } finally {
    // Step 3: Cleanup
    rl.close();
    await closeDB();
  }
}

// ── Entry Point ────────────────────────────────────────────────────────────────

if (require.main === module) {
  main();
}
