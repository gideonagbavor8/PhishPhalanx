# PhishPhalanx – Threat Intelligence & Phishing Incident Repository

## Overview
PhishPhalanx is an enterprise-style command-line threat intelligence platform designed to collect, catalog, and investigate phishing incidents in real time. It provides secure data ingestion for malicious hostnames, phishing indicators, and suspicious email metadata while offering a defensive storage workflow for raw email artifacts.

## Cloud Database
Cloud Firestore is used as the database for PhishPhalanx because it provides scalable NoSQL document storage, native real-time updates, and easy integration with Firebase security controls. Firestore is well suited for log-like incident records and high-speed blacklist lookups.

## Development Environment
This project is built with Node.js and the Firebase Admin SDK. It uses `dotenv` for environment configuration, local Firebase Emulator Suite support for safe offline testing, and standard CommonJS modules for compatibility with Node.js runtimes.

## Relational Diagram
Firestore collections and fields:

incidents
- incidentId
- targetDomain
- dangerLevel
- reporterEmail
- status
- timestamp
- reporter_metadata
- attachment_path

blacklists
- domainHash
- originalDomain
- addedAt
- malware_type
- date_added

## Video Walkthrough
[YouTube link here]

## Useful Websites
- [Firebase Docs](https://firebase.google.com/docs)
- [Firestore Data Modeling](https://firebase.google.com/docs/firestore/data-model)
- [Node.js Docs](https://nodejs.org/en/docs)

## Future Work
- [ ] Add user authentication with Firebase Auth
- [ ] Build a web dashboard for incident visualization
- [ ] Integrate live threat intelligence API feeds
