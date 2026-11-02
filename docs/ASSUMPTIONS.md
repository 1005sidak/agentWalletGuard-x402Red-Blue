# Architectural Assumptions and Design Baseline

This document records the foundational assumptions, confirmed design decisions, and system parameters for the x402 Red-Blue Payment Security System.

## 1. System Topology & Separability
- **Node Separability**: `blue/` and `red/` are two completely independent, deployable packages. Neither imports from the root workspace or from the peer node at runtime.
- **Contract Synchronization**: Shared contracts live authoritatively in `contracts/` and are copied verbatim to `blue/src/contracts/` and `red/src/contracts/` by `scripts/sync-contracts.ts`. Each synchronization generates a canonical `CONTRACTS_VERSION` and a SHA-256 hash manifest (`contracts.hash.json`).
- **Network Independence**: All hostnames and ports are decoupled into environment variables. Services bind to `0.0.0.0` for local area network (LAN) accessibility.

## 2. Chain as Financial Ground Truth
- Funds lost or protected are determined strictly by on-chain balance deltas reported by the mock blockchain (`:4040`), verified via cryptographic EIP-712 signatures for EIP-3009 `TransferWithAuthorization`.
- Guard and facilitator logs represent claims; the chain ledger represents proof.

## 3. Storage & Concurrency
- Primary storage is SQLite with Write-Ahead Logging (WAL) and `BEGIN IMMEDIATE` transactions to prevent budget race conditions.
- Implementations provide seamless support for `node:sqlite` (native in Node 22+) alongside `better-sqlite3`.

## 4. Default Rails & Units
- Rails: EVM only.
- Token: "TUSD" with 6 decimals.
- Amounts: Represented in atomic units as integer strings (e.g., `"1000000"` = 1.000000 TUSD).
- Chain ID: 31337.
