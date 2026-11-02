# Red Attacker Node (Laptop 2)

Offensive payment node providing:
- Hostile Merchant (:4020) with interactive product catalog and 402 mutator
- Mock Facilitator (:4030) implementing x402 1.2.0 settlement with simulated lying modes
- Attack Engine (A1–A18) with seeded replay and concurrency controls
- fast-check Property Mutation Fuzzer with regression export
- UCB1 + (1+lambda)-ES Learning Attacker
- Red Web Console (:4060) with global Kill Switch

## Requirements
- Node.js 20+ (Node 22 or 24 recommended)
- npm 10+

## Setup
1. Configure environment:
   ```bash
   cp .env.example .env
   # Set BLUE_HOST to Laptop 1's IP address
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Initialize / reset test keys and databases:
   ```bash
   npm run reset
   ```
4. Start all Red services:
   ```bash
   npm run red
   ```
   Or run standalone with mock Blue stub on localhost:
   ```bash
   npm run solo
   ```

## Operations
- Run all attacks: `npm run attacks:all`
- Run single attack: `npm run attacks -- --attack A1 --target BLUE_V1`
- Seeded attack run: `npm run attacks -- --seed 42 --target BLUE_V1`
- Run fuzzer: `npm run fuzz`
- Run learning attacker: `npm run learn`
