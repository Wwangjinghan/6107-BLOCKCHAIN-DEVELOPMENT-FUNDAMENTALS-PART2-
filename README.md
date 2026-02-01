# Track 7 – EVM Debugger (Blockchain Developer Tool)

This project implements a minimal EVM-level debugger based on Hardhat and JSON-RPC trace APIs.  
It demonstrates how to trace, parse, and analyze Ethereum transaction execution at opcode level.

The system focuses on:
- Fetching raw EVM execution traces (`debug_traceTransaction`)
- Parsing opcode-level logs (`structLogs`)
- Performing gas profiling
- Identifying key execution points such as `SSTORE`
- Generating structured JSON outputs for further visualization

This is a backend data layer for a blockchain debugger / gas profiler.

---

## 1. Tech Stack

- Node.js (>= 20)
- Hardhat v3
- viem
- JSON-RPC (debug_traceTransaction)
- JavaScript (ESM + CJS mixed)

---

## 2. Project Structure

fundamental_test/
├── contracts/
│ └── Demo.sol # Test contract
├── scripts/
│ ├── deploy_viem.cjs # Deploy + send transaction
│ ├── trace.js # Fetch EVM trace
│ ├── parse_trace.js # Parse trace & generate structured output
│ └── trace_call.js # (Optional) call-level trace (limited in Hardhat)
├── trace.json # Raw trace output
├── parsed_trace.json # Parsed structured trace (for UI)
├── hardhat.config.ts
├── package.json
└── README.md 


---

## 3. Quick Start

### Step 1: Install dependencies
```bash win+r 开cmd 切换到这个文件夹下执行
npm install

### Step 2: Start local blockchain

npx hardhat node 
``` 这是开启本地blockchain 一定!!! keep this terminal running !!! 不要关
出来类似：
Started HTTP and WebSocket JSON-RPC server at http://127.0.0.1:8545/
Accounts
========
WARNING: Funds sent on live network to accounts with publicly known private keys WILL BE LOST.

Account #0:  0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 (10000 ETH)
Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

Account #1:  0x70997970c51812dc3a010c7d01b50e0d17dc79c8 (10000 ETH)
Private Key: 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
...
让这个开着放着
### Step 3: Compile contracts 
# 在编译环境vscode终端切换成command prompt
输入 ：
node scripts/deploy_viem.cjs 

output example为： 

·deploy tx hash: 0x...
·contract address: 0x...
·set tx hash: 0x...

###Step 4 ###
```Copy the set tx hash into scripts/trace.js, then:

   node scripts/trace.js

```This generates:
```trace.json

###Step 5: Parse trace and generate debugger data ### 
node scripts/parse_trace.js


```This generates:
```parsed_trace.json
-----以上是目前我做到的步骤-----





4. What Has Been Implemented

4.1 Opcode-Level Trace
Uses debug_traceTransaction
Extracts full structLogs
Each step includes:
     program counter (pc)
     opcode (op)
     gas / gasCost
     stack top
     call depth
4.2 Gas Profiler
Aggregates gas usage by opcode:
 count per opcode
 total gas cost per opcode
Example:

SSTORE: 22100 gas
JUMP:   80 gas
PUSH1:  66 gas

4.3 Storage Write Detection
Automatically locates SSTORE operations and extracts:
 execution step
 storage slot
 value written
This enables direct observation of on-chain state changes.

4.4 Structured Output for UI
All parsed data is exported into:
    parsed_trace.json
Which can be directly consumed by a frontend debugger UI.

5. Known Limitations
Hardhat v3 local node does not support custom tracers
    callTracer is not available
    Only default structLogs are supported
Full call tree visualization requires:
    Geth or Erigon nodes (future work)

6. Future Extensions 

Frontend debugger UI (React / HTML)
Call tree visualization (with Geth)
Storage diff (pre/post state)
Memory viewer
Source mapping (Solidity ↔ EVM)

7. Educational Value
This project demonstrates:
     How blockchain debuggers work internally
     How Ethereum transactions execute at EVM level
     How gas costs emerge from low-level opcodes
     How developer tools like Remix / Tenderly are built

This is a developer infrastructure / security-oriented project.