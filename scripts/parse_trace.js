import fs from "fs";

const trace = JSON.parse(fs.readFileSync("trace.json", "utf8"));
const logs = trace.result.structLogs;
const STORAGE_SLOT_MAP = {
  "0x0": "x",
  "0x00": "x",
  "0000000000000000000000000000000000000000000000000000000000000000": "x"
};


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
    const slot = stack[stack.length - 1];
    const value = stack[stack.length - 2];

    const variable =
      slot === "0000000000000000000000000000000000000000000000000000000000000000"
        ? "x"
        : "x";

    sstores.push({
      step: idx,
      slot,
      value,
      variable
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
