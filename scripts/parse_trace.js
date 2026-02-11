const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");

// Configuration
const RPC_URL = "http://127.0.0.1:8545";
const provider = new ethers.JsonRpcProvider(RPC_URL);

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

// Example ABI
const ABI = [
    "event Transfer(address indexed from, address indexed to, uint256 value)"
];

const FUNCTION_SELECTORS = {
    "0x60fe47b1": "set(uint256)",
    "0x0c55699c": "get()"
};

/**
 * Gas Optimization Suggestions Rule Engine
 */
function generateGasOptimizationSuggestions(rows, topOps, totalGasUsed) {
    const suggestions = [];
    const totalGas = parseInt(totalGasUsed);

    // Rule 1: Detect frequent SSTORE operations
    const sstoreOp = topOps.find(op => op.op === 'SSTORE');
    if (sstoreOp && sstoreOp.gasCostSum > 5000) {
        suggestions.push({
            severity: "high",
            title: "Optimize SSTORE operations",
            description: "Detected frequent SSTORE operations, consider using storage optimization mode or Solidity packed storage.",
            estimatedGasSavings: Math.floor(sstoreOp.gasCostSum * 0.1),
            rule: "sstoreOptimization"
        });
    }

    // Rule 2: Detect repeated operations
    const dupOp = topOps.find(op => op.op === 'DUP1' || op.op === 'DUP2');
    if (dupOp && dupOp.count > 10) {
        suggestions.push({
            severity: "medium",
            title: "Reduce repeated stack operations",
            description: "Detected multiple DUP operations, consider reorganizing logic to reduce stack operations.",
            estimatedGasSavings: Math.floor(dupOp.gasCostSum * 0.05),
            rule: "reduceStackOps"
        });
    }

    // Rule 3: Detect JUMP patterns
    const jumpOps = topOps.filter(op => op.op.includes('JUMP'));
    const totalJumpGas = jumpOps.reduce((sum, op) => sum + op.gasCostSum, 0);
    if (totalJumpGas > totalGas * 0.15) {
        suggestions.push({
            severity: "medium",
            title: "Optimize control flow",
            description: "Detected frequent JUMP operations, consider using inline functions or reducing branches.",
            estimatedGasSavings: Math.floor(totalJumpGas * 0.1),
            rule: "optimizeControlFlow"
        });
    }

    // Rule 4: Detect RETURN/REVERT
    const returnOps = topOps.filter(op => op.op === 'RETURN' || op.op === 'REVERT');
    if (returnOps.length > 2) {
        suggestions.push({
            severity: "low",
            title: "Merge return paths",
            description: "Detected multiple return paths, consider merging to reduce code duplication.",
            estimatedGasSavings: 100,
            rule: "mergeReturnPaths"
        });
    }

    // Rule 5: Detect PUSH operations
    const pushOps = topOps.filter(op => op.op.startsWith('PUSH'));
    const totalPushGas = pushOps.reduce((sum, op) => sum + op.gasCostSum, 0);
    if (totalPushGas > totalGas * 0.1) {
        suggestions.push({
            severity: "low",
            title: "Consider constant inlining",
            description: "Detected frequent PUSH operations, consider constant folding during compilation.",
            estimatedGasSavings: Math.floor(totalPushGas * 0.05),
            rule: "constantInlining"
        });
    }

    return suggestions;
}

/**
 * Build Call Tree
 */
function buildCallTree(rows) {
    const callStack = [];
    const callTree = [];
    let callId = 0;

    rows.forEach((row, index) => {
        if (row.isCall) {
            const newCall = {
                id: callId++,
                step: row.step,
                pc: row.pc,
                op: row.op,
                depth: row.depth,
                startGas: row.gas,
                children: []
            };

            if (callStack.length > 0) {
                callStack[callStack.length - 1].children.push(newCall);
            } else {
                callTree.push(newCall);
            }

            callStack.push(newCall);
        } else if (row.op === 'RETURN' || row.op === 'REVERT') {
            // This cannot accurately detect call termination, but as a simplified version
            if (callStack.length > 0 && index > 0) {
                const currentDepth = row.depth;
                while (callStack.length > 0 && callStack[callStack.length - 1].depth >= currentDepth) {
                    callStack.pop();
                }
            }
        }
    });

    return callTree;
}


/**
 * Normalize Slot data
 */
function normalizeSlot(slot) {
    if (!slot) return ''.padStart(64, '0');
    const clean = slot.startsWith("0x") ? slot.slice(2) : slot;
    return clean.padStart(64, "0");
}

/**
 * Handle BigInt serialization in JSON.stringify
 */
function bigIntReplacer(key, value) {
    return typeof value === 'bigint' ? value.toString() : value;
}

async function parseTrace() {
    try {
        const traceFile = path.join(__dirname, "../trace.json");
        const outFile = path.join(__dirname, "../frontend/parsed_trace.json");

        if (!fs.existsSync(traceFile)) {
            console.error("❌ Error: Cannot find trace.json file, path:", traceFile);
            return;
        }

        const traceData = JSON.parse(fs.readFileSync(traceFile, "utf-8"));
        
        // Support different trace export formats
        const structLogs = traceData.result?.structLogs || traceData.tx?.structLogs || traceData.structLogs || [];

        // Support passing txHash from command line or fallback to common fields
        const cliTxHash = process.argv[2];
        let txHash = cliTxHash || traceData.tx?.hash || traceData.hash || traceData.result?.hash || traceData.transactionHash || traceData.result?.transactionHash;

        // If txHash is not found, try extracting from scripts/trace.js
        if (!txHash) {
            try {
                const traceJsPath = path.join(__dirname, "../scripts/trace.js");
                if (fs.existsSync(traceJsPath)) {
                    const traceJs = fs.readFileSync(traceJsPath, "utf-8");
                    const m = traceJs.match(/txHash\s*=\s*["'](0x[a-fA-F0-9]{64})["']/);  
                    if (m) {
                        txHash = m[1];
                        console.log(`Auto-read txHash from scripts/trace.js: ${txHash}`);
                    }
                }
            } catch (e) {
                // ignore
            }
        }

        if (!txHash) {
            console.error("❌ Cannot extract transaction hash (txHash) from trace file.");
            console.error("Solution:\n 1) Pass txHash as parameter: node scripts/parse_trace.cjs <txHash>\n 2) Ensure trace.json contains tx.hash or hash field\n 3) Or define txHash constant in scripts/trace.js (auto-read)");
            return;
        }

        console.log(`Processing transaction: ${txHash}`);

        // Fetch on-chain data
        const [receipt, tx] = await Promise.all([
            provider.getTransactionReceipt(txHash),
            provider.getTransaction(txHash)
        ]);

        if (!receipt) throw new Error("Cannot get transaction receipt, ensure local node contains this transaction");

        const blockNumber = receipt.blockNumber;
        const contractAddress = receipt.to;

        // ==================== Initialize all data structures ====================
        const rows = [];
        const sstores = [];
        const storageDiff = [];
        const balanceChanges = [];
        const transfers = [];
        const decodedEvents = [];
        const gasOptimizationSuggestions = [];
        const callTree = [];
        const functionGasProfile = [];
        
        const opCounts = {};
        const opGas = {};

        // ============= 1. Process instruction stream (structLogs) =============
        structLogs.forEach((log, index) => {
            const op = log.op || "UNKNOWN";
            const gasCost = parseInt(log.gasCost || 0);

            opCounts[op] = (opCounts[op] || 0) + 1;
            opGas[op] = (opGas[op] || 0) + gasCost;

            const stack = log.stack || [];
            const isStorage = op === "SSTORE";

            if (isStorage && stack.length >= 2) {
                // EVM Stack is LIFO, SSTORE [slot, value]
                const slotHex = stack[stack.length - 1];
                const valueHex = stack[stack.length - 2];

                sstores.push({
                    step: index + 1,
                    slot: normalizeSlot(slotHex),
                    value: normalizeSlot(valueHex),
                    variable: normalizeSlot(slotHex)
                });
            }

            rows.push({
                step: index + 1,
                pc: log.pc ?? 0,
                op,
                gas: log.gas ?? 0,
                gasCost,
                depth: log.depth ?? 0,
                isJump: op.startsWith("JUMP"),
                isCall: op.includes("CALL"),
                isStorage,
                stackTop: stack[stack.length - 1] ?? "",
                stackTop3: stack.slice(-3).reverse()
            });
        });

        // ============= 2. Process state changes (Storage Diff) =============
        for (const s of sstores) {
            const slotHex = "0x" + s.slot;
            try {
                const prevBlock = blockNumber > 0 ? blockNumber - 1 : 0;
                const before = await provider.getStorage(contractAddress, slotHex, prevBlock);
                const after = await provider.getStorage(contractAddress, slotHex, blockNumber);

                storageDiff.push({
                    slot: s.slot,
                    before,
                    after
                });
            } catch (e) {
                console.warn(`Skipping storage comparison for Slot ${slotHex}: ${e.message}`);
            }
        }

        // ============= 3. Balance changes =============
        try {
            const prevBlock = blockNumber > 0 ? blockNumber - 1 : 0;
            const fromBefore = await provider.getBalance(tx.from, prevBlock);
            const fromAfter = await provider.getBalance(tx.from, blockNumber);

            balanceChanges.push({
                address: tx.from,
                before: fromBefore.toString(),
                after: fromAfter.toString()
            });
        } catch (e) {
            console.warn(`Balance query failed: ${e.message}`);
        }

        // ============= 4. Event parsing =============
        const iface = new ethers.Interface(ABI);
        receipt.logs.forEach(log => {
            // Parse standard ERC20 Transfer
            if (log.topics[0] === TRANSFER_TOPIC && log.topics.length >= 3) {
                const from = ethers.getAddress("0x" + log.topics[1].slice(26));
                const to = ethers.getAddress("0x" + log.topics[2].slice(26));
                const amount = ethers.getBigInt(log.data || "0").toString();

                transfers.push({
                    token: log.address,
                    from, to, amount
                });
            }

            // Parse custom ABI events
            try {
                const parsed = iface.parseLog(log);
                if (parsed) {
                    decodedEvents.push({
                        name: parsed.name,
                        args: parsed.args
                    });
                }
            } catch (e) { /* Ignore unparseable events */ }
        });

        // ============= 5. Generate topOps summary =============
        const topOps = Object.entries(opCounts)
            .map(([op, count]) => ({
                op,
                count,
                gasCostSum: opGas[op] || 0
            }))
            .sort((a, b) => b.gasCostSum - a.gasCostSum);

        // ============= 6. Build callTree =============
        const builtCallTree = buildCallTree(rows);
        callTree.push(...builtCallTree);

        // ============= 7. Generate function gas analysis =============
        const selector = tx.data.slice(0, 10);
        functionGasProfile.push({
            selector,
            functionName: FUNCTION_SELECTORS[selector] || "unknown",
            totalGasUsed: receipt.gasUsed.toString(),
            gasPerInstruction: Math.floor(parseInt(receipt.gasUsed) / rows.length)
        });

        // ============= 8. Generate gas optimization suggestions =============
        const suggestions = generateGasOptimizationSuggestions(rows, topOps, receipt.gasUsed.toString());
        gasOptimizationSuggestions.push(...suggestions);

        // ============= 9. Build final output =============
        const output = {
            rows,
            topOps,
            sstores,
            storageDiff,
            transfers,
            balanceChanges,
            functionGasProfile,
            gasOptimizationSuggestions,
            callTree,
            decodedEvents
        };

        // Write to file, using bigIntReplacer to handle serialization
        fs.mkdirSync(path.dirname(outFile), { recursive: true });
        fs.writeFileSync(outFile, JSON.stringify(output, bigIntReplacer, 2));
        
        console.log(` Parsing completed! Results saved to: ${outFile}`);
        console.log(` Statistics:`);
        console.log(`  - Total instruction steps: ${rows.length}`);
        console.log(`  - SSTORE operations: ${sstores.length}`);
        console.log(`  - Storage changes: ${storageDiff.length}`);
        console.log(`  - Transfer events: ${transfers.length}`);
        console.log(`  - Parsed events: ${decodedEvents.length}`);
        console.log(`  - Call tree depth: ${Math.max(...callTree.map(c => c.depth || 1), 0)}`);
        console.log(`  - Gas optimization suggestions: ${gasOptimizationSuggestions.length}`);

    } catch (error) {
        console.error("❌ Script execution failed:", error);
    }
}


parseTrace();
