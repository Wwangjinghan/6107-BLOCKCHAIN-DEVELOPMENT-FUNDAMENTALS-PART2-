const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

// ====== 配置 ======
const RPC_URL = "http://127.0.0.1:8545";
const provider = new ethers.JsonRpcProvider(RPC_URL);

// ERC20 Transfer 事件 topic
const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

// ====== 工具函数 ======
function normalizeSlot(slot) {
  if (!slot) return ''.padStart(64, '0');
  const clean = slot.startsWith('0x') ? slot.slice(2) : slot;
  return clean.padStart(64, '0');
}

async function parseTrace() {
  const traceFile = path.join(__dirname, '../trace.json');
  const outFile = path.join(__dirname, '../parsed_trace.json');

  if (!fs.existsSync(traceFile)) {
    console.error('trace.json not found');
    process.exit(1);
  }

  const trace = JSON.parse(fs.readFileSync(traceFile, 'utf-8'));
  const structLogs =
    trace.result?.structLogs ||
    trace.tx?.structLogs ||
    [];

  const txHash = trace.tx?.hash || trace.hash;
  if (!txHash) {
    console.error("❌ tx hash not found in trace.json");
    process.exit(1);
  }

  const receipt = await provider.getTransactionReceipt(txHash);
  const tx = await provider.getTransaction(txHash);

  const blockNumber = receipt.blockNumber;
  const contractAddress = receipt.to;

  const rows = [];
  const sstores = [];
  const storageDiff = [];
  const transfers = [];
  const balanceChanges = [];

  const opCounts = {};
  const opGas = {};

  // ======================
  // Trace 解析
  // ======================
  structLogs.forEach((log, index) => {
    const op = log.op || 'UNKNOWN';

    opCounts[op] = (opCounts[op] || 0) + 1;
    opGas[op] = (opGas[op] || 0) + (log.gasCost || 0);

    const stack = log.stack || [];

    const isStorage = op === 'SSTORE';

    if (isStorage && stack.length >= 2) {
      const valueHex = stack[stack.length - 2];
      const slotHex = stack[stack.length - 1];

      const slotNorm = normalizeSlot(slotHex);
      const valueNorm = normalizeSlot(valueHex);

      sstores.push({
        step: index + 1,
        slot: slotNorm,
        value: valueNorm,
        variable: slotNorm
      });
    }

    rows.push({
      step: index + 1,
      pc: log.pc ?? 0,
      op,
      gas: log.gas ?? 0,
      gasCost: log.gasCost ?? 0,
      depth: log.depth ?? 0,
      isJump: op.startsWith('JUMP'),
      isCall: op.includes('CALL'),
      isStorage,
      stackTop: stack[stack.length - 1] ?? '',
      stackTop3: stack.slice(-3).reverse()
    });
  });

  // ======================
  // 真正 Storage Diff
  // ======================
  for (const s of sstores) {
    const slotHex = "0x" + s.slot;

    const before = await provider.getStorage(
      contractAddress,
      slotHex,
      blockNumber - 1
    );

    const after = await provider.getStorage(
      contractAddress,
      slotHex,
      blockNumber
    );

    storageDiff.push({
      slot: s.slot,
      variable: s.variable,
      before,
      after
    });
  }

  // ======================
  // Balance Changes
  // ======================
  const fromBefore = await provider.getBalance(tx.from, blockNumber - 1);
  const fromAfter = await provider.getBalance(tx.from, blockNumber);

  balanceChanges.push({
    address: tx.from,
    before: fromBefore.toString(),
    after: fromAfter.toString()
  });

  if (tx.to) {
    const toBefore = await provider.getBalance(tx.to, blockNumber - 1);
    const toAfter = await provider.getBalance(tx.to, blockNumber);

    balanceChanges.push({
      address: tx.to,
      before: toBefore.toString(),
      after: toAfter.toString()
    });
  }

  // ======================
  // ERC20 Transfer 解析
  // ======================
  receipt.logs.forEach(log => {
    if (log.topics[0] === TRANSFER_TOPIC) {
      const from = "0x" + log.topics[1].slice(26);
      const to = "0x" + log.topics[2].slice(26);
      const amount = ethers.getBigInt(log.data).toString();

      transfers.push({
        token: log.address,
        from,
        to,
        amount
      });
    }
  });

  // ======================
  // Gas Profiling
  // ======================
  const topOps = Object.entries(opCounts)
    .map(([op, count]) => ({
      op,
      count,
      gasCostSum: opGas[op] || 0
    }))
    .sort((a, b) => b.gasCostSum - a.gasCostSum)
    .slice(0, 10);

  // ======================
  // 最终输出
  // ======================
  const output = {
    rows,
    topOps,
    sstores,
    storageDiff,
    transfers,
    balanceChanges
  };

  fs.writeFileSync(outFile, JSON.stringify(output, null, 2));

  console.log("✓ parsed_trace.json generated");
}

parseTrace();

