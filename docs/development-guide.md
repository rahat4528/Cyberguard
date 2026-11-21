# Development Guide

## Prerequisites
- Node.js (v20+ recommended)
- Docker & Docker Compose (optional for local multi-service orchestration)
- PostgreSQL (or local SQLite/in-memory drivers for isolated tests)

## Running Phase 1 (Authentication System)
```bash
cd 01-authentication-system-oauth
npm install
npm test
npm run dev
```

## Running Phase 2 (Password Manager)
```bash
cd 02-password-manager
npm install
npm test
npm run dev
```

## Running Phase 3 (Two-Factor Authenticator)
```bash
cd 03-two-factor-authentication-system
npm install
npm test
npm run dev
```
