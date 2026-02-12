#!/usr/bin/env node
// Lightweight local trace parser: reads trace.json (geth/tenderly style) and writes parsed_trace.json
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const demoMode = args.includes('--demo');

const traceFile = path.join(__dirname, '../trace.json');
const outFile = path.join(__dirname, '../parsed_trace.json');

if (!fs.existsSync(traceFile)) {
  console.error('trace.json not found');
  process.exit(1);
}

const traceData = JSON.parse(fs.readFileSync(traceFile, 'utf-8'));
const structLogs = traceData.result?.structLogs || traceData.tx?.structLogs || [];

const rows = [];
const sstores = [];
const opCounts = {};
const opGas = {};

structLogs.forEach((log, idx) => {
  const op = log.op || 'UNKNOWN';
  const gasCost = parseInt(log.gasCost || 0);
  opCounts[op] = (opCounts[op] || 0) + 1;
  opGas[op] = (opGas[op] || 0) + gasCost;
  const stack = log.stack || [];
  const isStorage = op === 'SSTORE';
  if (isStorage && stack.length >= 2) {
    const slot = stack[stack.length - 1] || '';
    sstores.push({ step: idx + 1, slot: slot.replace(/^0+/, ''), value: stack[stack.length - 2] || '' });
  }
  rows.push({
    step: idx + 1,
    pc: log.pc ?? 0,
    op,
    gas: log.gas ?? 0,
    gasCost,
    depth: log.depth ?? 0,
    isJump: (op || '').startsWith('JUMP'),
    isCall: (op || '').includes('CALL'),
    isStorage,
    stackTop: stack[stack.length - 1] ? ('0x' + stack[stack.length - 1]) : '',
    stackTop3: (stack.slice(-3).map(s => '0x' + s))
  });
});

const topOps = Object.entries(opCounts).map(([op, count]) => ({ op, count, gasCostSum: opGas[op] })).sort((a,b)=>b.gasCostSum - a.gasCostSum);

function buildCallTree(rows) {
  const callStack = [];
  const callTree = [];
  let callId = 0;
  rows.forEach((row) => {
    // Only real external call opcodes create call tree nodes, not pseudo-calls like CALLVALUE/CALLDATALOAD
    if (['CALL','DELEGATECALL','STATICCALL','CALLCODE'].includes(row.op)) {
      const newCall = { id: callId++, step: row.step, pc: row.pc, op: row.op, depth: row.depth, children: [] };
      if (callStack.length > 0) callStack[callStack.length - 1].children.push(newCall); else callTree.push(newCall);
      callStack.push(newCall);
    } else if (row.op === 'RETURN' || row.op === 'REVERT') {
      if (callStack.length > 0) {
        const currentDepth = row.depth;
        while (callStack.length > 0 && callStack[callStack.length - 1].depth >= currentDepth) callStack.pop();
      }
    }
  });
  return callTree;
}

function generateGasSuggestions(topOps, totalGas) {
  const suggestions = [];
  const sstoreOp = topOps.find(o => o.op === 'SSTORE');
  if (sstoreOp && (sstoreOp.gasCostSum || 0) > 5000) {
    suggestions.push({ severity: 'high', title: 'Optimize SSTORE', description: 'Frequent storage writes detected.', estimatedGasSavings: Math.floor((sstoreOp.gasCostSum||0) * 0.1), rule: 'sstoreOptimization' });
  }
  return suggestions;
}

// simple callFrames/stepToFrameId construction using depth
const stepToFrameId = new Array(rows.length).fill(null);
const callFrames = [];
let nextFrameId = 0;
const frameStack = [];

rows.forEach((row, idx) => {
  // if a CALL-like op, create frame
  if (['CALL','DELEGATECALL','STATICCALL','CALLCODE'].includes(row.op)) {
    const frame = { id: nextFrameId++, step: row.step, pc: row.pc, op: row.op, depth: row.depth, type: row.op, children: [], to: null };
    if (frameStack.length > 0) frameStack[frameStack.length-1].children.push(frame); else callFrames.push(frame);
    frameStack.push(frame);
    stepToFrameId[idx] = frame.id;
  } else {
    stepToFrameId[idx] = frameStack.length>0 ? frameStack[frameStack.length-1].id : null;
  }
  if (row.op === 'RETURN' || row.op === 'REVERT') {
    while (frameStack.length>0 && frameStack[frameStack.length-1].depth >= row.depth) frameStack.pop();
  }
});

// attach storageSlotName
const sstoreByStep = {};
sstores.forEach(s=>{ sstoreByStep[s.step]=s; });
rows.forEach(r=>{ if (r.isStorage && sstoreByStep[r.step]) r.storageSlotName = '0x' + (sstoreByStep[r.step].slot || '').replace(/^0x/,''); });
let callTree = buildCallTree(rows);
const totalGas = rows.reduce((acc, r) => acc + (r.gasCost || 0), 0);
let gasSuggestions = generateGasSuggestions(topOps, totalGas);

// demo mode: inject synthetic callTree and additional gas suggestions for demo recording
if (demoMode) {
  callTree = [
    { id: 0, step: 34, pc: 84, op: 'CALL', depth: 1, type: 'CALL', children: [
      { id: 1, step: 66, pc: 187, op: 'CALL', depth: 2, type: 'CALL', children: [] }
    ]},
    { id: 2, step: 118, pc: 210, op: 'DELEGATECALL', depth: 1, type: 'DELEGATECALL', children: [] }
  ];
  gasSuggestions.push(
    { severity: 'medium', title: 'Reduce Function Complexity', description: 'Consider splitting complex logic into smaller functions to reduce bytecode size.', estimatedGasSavings: 850, rule: 'functionComplexity' },
    { severity: 'low', title: 'Optimize Loops', description: 'Cache array length in loops to avoid repeated storage reads.', estimatedGasSavings: 320, rule: 'loopOptimization' }
  );
}

const output = { rows, topOps, sstores, callFrames, stepToFrameId, callTree, gasSuggestions, totalGas };
fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
console.log('✓ parsed_trace.json generated (local)' + (demoMode ? ' [DEMO MODE]' : ''));
