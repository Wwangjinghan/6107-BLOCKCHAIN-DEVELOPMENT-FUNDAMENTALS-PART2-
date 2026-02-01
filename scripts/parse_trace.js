import fs from "node:fs";

function main() {
  const raw = JSON.parse(fs.readFileSync("trace.json", "utf8"));
  const logs = raw?.result?.structLogs ?? [];
  if (!logs.length) {
    console.error("No structLogs found.");
    process.exit(1);
  }

  // 1) opcode 表（前 30 条预览）
 const rows = logs.map((s, i) => ({
  step: i,
  pc: s.pc,
  op: s.op,
  gas: s.gas,
  gasCost: s.gasCost,
  depth: s.depth,
  stackTop: Array.isArray(s.stack) && s.stack.length ? s.stack[s.stack.length - 1] : null,
  stackTop3: Array.isArray(s.stack) ? s.stack.slice(-3) : [],
  isStorage: s.op === "SSTORE" || s.op === "SLOAD",
  isCall: ["CALL","DELEGATECALL","STATICCALL","CALLCODE","CREATE","CREATE2"].includes(s.op),
  isJump: s.op === "JUMP" || s.op === "JUMPI" || s.op === "JUMPDEST",
}));


  console.log("=== Preview (first 30 steps) ===");
  console.table(rows.slice(0, 30));

  // 2) gas profiler：统计每种 opcode 出现次数 & gasCost 总和
  const agg = new Map();
  for (const s of logs) {
    const key = s.op;
    const cur = agg.get(key) ?? { op: key, count: 0, gasCostSum: 0 };
    cur.count += 1;
    cur.gasCostSum += Number(s.gasCost ?? 0);
    agg.set(key, cur);
  }

  const top = [...agg.values()]
    .sort((a, b) => b.gasCostSum - a.gasCostSum)
    .slice(0, 15);

  console.log("=== Top ops by gasCostSum (rough) ===");
  console.table(top);

  // 3) storage 写入点（先抓 SSTORE 步）
  const sstores = rows.filter((r) => r.op === "SSTORE");
  console.log(`=== SSTORE steps: ${sstores.length} ===`);
  console.table(sstores.slice(0, 20));

  // 导出给前端用
  fs.writeFileSync("parsed_trace.json", JSON.stringify({ tx: raw?.result, rows, topOps: top, sstores }, null, 2));
  console.log("saved parsed_trace.json");
}

main();
