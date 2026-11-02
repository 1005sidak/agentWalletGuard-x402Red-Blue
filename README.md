# x402 Red–Blue Payment Security System (Monorepo, Two Deployable Nodes)

A dual-node offensive and defensive payment security research platform for testing the x402 payment protocol under simulated attack conditions.

## Architecture
- **`blue/` (Defender Node - Laptop 1)**: Runs an AI shopping agent, the 9-layer security guard (L0–L8), mock blockchain with EIP-3009 settlement, event collector, and Blue Dashboard.
- **`red/` (Attacker Node - Laptop 2)**: Runs a hostile merchant, mock facilitator, 18 attack vectors (A1–A18), fast-check mutation fuzzer, UCB1 + evolution strategy learner, and Red Console.
- **`contracts/` (Source of Truth)**: Central schemas, reason codes, attack specifications, and API definitions. Vendored into both `blue/` and `red/` with SHA-256 integrity verification.

## Running Solo (Single Laptop Development)
```bash
npm install
npm run sync:contracts
npm run solo
```
Access the interfaces:
- Blue Dashboard: [http://localhost:4050](http://localhost:4050)
- Red Console: [http://localhost:4060](http://localhost:4060)

## Deploying to Two Laptops over LAN
1. Run packaging script:
   ```bash
   npm run split
   ```
2. Copy `dist/blue.zip` to Laptop 1 and `dist/red.zip` to Laptop 2.
3. On Laptop 1:
   ```bash
   unzip blue.zip && cd blue
   cp .env.example .env # Set RED_HOST=<Laptop 2 IP>
   npm install && npm run reset && npm run blue
   ```
4. On Laptop 2:
   ```bash
   unzip red.zip && cd red
   cp .env.example .env # Set BLUE_HOST=<Laptop 1 IP>
   npm install && npm run reset && npm run red
   ```
