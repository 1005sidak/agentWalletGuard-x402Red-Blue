# Blue Defender Node (Laptop 1)

Defensive payment node providing:
- Express AI Shopping Assistant API (:4010)
- 9-Layer Defense Guard (L0–L8) with wallet signing firewall
- Mock Blockchain (:4040) ledger and EIP-3009 settlement engine
- Security Event Collector (:4050) with SSE streaming, alarms, and the Blue Dashboard

## Requirements
- Node.js 20+ (Node 22 or 24 recommended)
- npm 10+

## Setup
1. Configure environment:
   ```bash
   cp .env.example .env
   # Set RED_HOST to Laptop 2's IP address
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Initialize / reset test keys and databases:
   ```bash
   npm run reset
   ```
4. Start all Blue services:
   ```bash
   npm run blue
   ```
   Or run standalone with mock Red stub on localhost:
   ```bash
   npm run solo
   ```

## Test Commands
- `npm run test:spike` — Wallet signing firewall compatibility spike
- `npm run test:guard` — Unit tests for layers L0 through L8
- `npm run test:honest` — 200 honest payments test suite
- `npm run test:attacks` — Attack suite replay against Naive, Blue V0, and Blue V1
