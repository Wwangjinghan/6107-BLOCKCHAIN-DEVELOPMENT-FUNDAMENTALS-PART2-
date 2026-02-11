const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
const { execSync } = require('child_process');

// ====== 配置 ======
const RPC_URL = "http://127.0.0.1:8545";
const provider = new ethers.JsonRpcProvider(RPC_URL);

// ERC20 & ABI 配置
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ABI = ["event Transfer(address indexed from, address indexed to, uint256 value)"];
const FUNCTION_SELECTORS = {
    "0x60fe47b1": "set(uint256)",
    "0x0c55699c": "get()"
};

// ====== 核心工具函数 ======
function normalizeSlot(slot) {
    if (!slot) return ''.padStart(64, '0');
    const clean = slot.startsWith('0x') ? slot.slice(2) : slot;
    return clean.padStart(64, '0');
}

function bigIntReplacer(key, value) {
    return typeof value === 'bigint' ? value.toString() : value;
}

// ====== 逻辑引擎 ======

/**
 * 1. Gas 优化建议引擎
 */
function generateGasSuggestions(topOps, totalGas) {
    const suggestions = [];
    const sstoreOp = topOps.find(o => o.op === 'SSTORE');
    if (sstoreOp && sstoreOp.gasCostSum > 5000) {
        suggestions.push({
            severity: "high",
            title: "Optimize SSTORE",
            description: "Frequent storage writes detected.",
            estimatedGasSavings: Math.floor(sstoreOp.gasCostSum * 0.1),
            rule: "sstoreOptimization"
        });
    }
    // ... 可继续添加其他 Rule 2/3/4/5
    return suggestions;
}

/**
 * 2. 构建调用树 (Call Tree)
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
            if (callStack.length > 0) {
                const currentDepth = row.depth;
                while (callStack.length > 0 && callStack[callStack.length - 1].depth >= currentDepth) {
                    callStack.pop();
                }
            }
        }
    });
    return callTree;
}

// ====== 主解析函数 ======
async function parseTrace() {
    const traceFile = path.join(__dirname, '../trace.json');
    const outFile = path.join(__dirname, '../frontend/parsed_trace.json');

    if (!fs.existsSync(traceFile)) {
        console.error('trace.json not found');
        return;
    }

    const traceData = JSON.parse(fs.readFileSync(traceFile, 'utf-8'));
    const structLogs = traceData.result?.structLogs || traceData.tx?.structLogs || [];
    const txHash = traceData.tx?.hash || traceData.hash || process.argv[2];

    if (!txHash) {
        console.error("❌ txHash missing");
        return;
    }

    // 获取链上上下文
    const [receipt, tx] = await Promise.all([
        provider.getTransactionReceipt(txHash),
        provider.getTransaction(txHash)
    ]);

    const blockNumber = receipt.blockNumber;
    const contractAddress = receipt.to;

    // 初始化数据容器
    const rows = [];
    const sstores = [];
    const storageDiff = [];
    const balanceChanges = [];
    const transfers = [];
    const opCounts = {};
    const opGas = {};

    // 1. 解析指令流
    structLogs.forEach((log, index) => {
        const op = log.op || 'UNKNOWN';
        const gasCost = parseInt(log.gasCost || 0);
        opCounts[op] = (opCounts[op] || 0) + 1;
        opGas[op] = (opGas[op] || 0) + gasCost;

        const stack = log.stack || [];
        const isStorage = op === 'SSTORE';

        if (isStorage && stack.length >= 2) {
            const slot = normalizeSlot(stack[stack.length - 1]);
            sstores.push({
                step: index + 1,
                slot: slot,
                value: normalizeSlot(stack[stack.length - 2]),
                variable: slot // 如果有源码映射，这里可以替换为变量名
            });
        }

        rows.push({
            step: index + 1,
            pc: log.pc ?? 0,
            op,
            gas: log.gas ?? 0,
            gasCost,
            depth: log.depth ?? 0,
            isJump: op.startsWith('JUMP'),
            isCall: op.includes('CALL'),
            isStorage,
            stackTop: stack[stack.length - 1] ?? ''
        });
    });

    // 2. 获取存储变更详情 (Storage Diff)
    for (const s of sstores) {
        const before = await provider.getStorage(contractAddress, "0x" + s.slot, blockNumber - 1);
        const after = await provider.getStorage(contractAddress, "0x" + s.slot, blockNumber);
        storageDiff.push({ slot: s.slot, before, after });
    }

    // 3. 获取 ETH 余额变动
    const fromBefore = await provider.getBalance(tx.from, blockNumber - 1);
    const fromAfter = await provider.getBalance(tx.from, blockNumber);
    balanceChanges.push({
        address: tx.from,
        before: fromBefore.toString(),
        after: fromAfter.toString()
    });

    // 4. 解析 ERC20 转账
    receipt.logs.forEach(log => {
        if (log.topics[0] === TRANSFER_TOPIC && log.topics.length >= 3) {
            transfers.push({
                token: log.address,
                from: ethers.getAddress("0x" + log.topics[1].slice(26)),
                to: ethers.getAddress("0x" + log.topics[2].slice(26)),
                amount: ethers.getBigInt(log.data || "0").toString()
            });
        }
    });

    // 5. 性能与分析总结
    const topOps = Object.entries(opCounts)
        .map(([op, count]) => ({ op, count, gasCostSum: opGas[op] }))
        .sort((a, b) => b.gasCostSum - a.gasCostSum);

    const callTree = buildCallTree(rows);
    const gasSuggestions = generateGasSuggestions(topOps, receipt.gasUsed);

    // 6. 合并输出
    const output = {
        transaction: {
            hash: txHash,
            from: tx.from,
            to: tx.to,
            gasUsed: receipt.gasUsed.toString(),
            status: receipt.status
        },
        analysis: {
            topOps,
            gasSuggestions,
            callTree,
            functionProfile: {
                selector: tx.data.slice(0, 10),
                name: FUNCTION_SELECTORS[tx.data.slice(0, 10)] || "unknown"
            }
        },
        execution: {
            rows,
            sstores,
            storageDiff,
            transfers,
            balanceChanges
        }
    };

    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    fs.writeFileSync(outFile, JSON.stringify(output, bigIntReplacer, 2));
    console.log(`✓ Parsed trace saved to ${outFile}`);
}

parseTrace();
