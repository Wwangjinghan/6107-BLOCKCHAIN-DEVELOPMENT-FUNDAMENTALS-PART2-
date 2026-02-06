import fs from "fs";

const trace = JSON.parse(fs.readFileSync("trace.json", "utf8"));
const logs = trace.result.structLogs;
const STORAGE_SLOT_MAP = {
  "0000000000000000000000000000000000000000000000000000000000000000": "x"
};
;


// ===== rows =====
const rows = [];

// ===== gas profiler =====
const gasMap = {};

// ===== sstores =====
const sstores = [];

logs.forEach((log, idx) => {
  const stack = log.stack || [];
  const stackTop = stack.slice(-3);

  // rows
  rows.push({
    step: idx,
    pc: log.pc,
    op: log.op,
    gasCost: log.gasCost,
    depth: log.depth,
    stackTop
  });

  // gas profiler
  gasMap[log.op] = gasMap[log.op] || { count: 0, gas: 0 };
  gasMap[log.op].count += 1;
  gasMap[log.op].gas += log.gasCost;

  // SSTORE decode
    if (log.op === "SSTORE" && stack.length >= 2) {
    const rawSlot = stack[stack.length - 1];
    const rawValue = stack[stack.length - 2];

    // 统一 slot 格式：32-byte hex，无 0x
    const slot = rawSlot.padStart(64, "0");
    const value = rawValue.padStart(64, "0");

    sstores.push({
      step: idx,
      slot,
      value,
      variable: STORAGE_SLOT_MAP[slot] || "unknown"
    });
  }


});

// ===== topOps =====
const topOps = Object.entries(gasMap)
  .map(([op, v]) => ({
    op,
    count: v.count,
    gas: v.gas
  }))
  .sort((a, b) => b.gas - a.gas);

// ===== final output =====
const output = {
  rows,
  topOps,
  sstores
};

fs.writeFileSync("parsed_trace.json", JSON.stringify(output, null, 2));
console.log("saved parsed_trace.json");
