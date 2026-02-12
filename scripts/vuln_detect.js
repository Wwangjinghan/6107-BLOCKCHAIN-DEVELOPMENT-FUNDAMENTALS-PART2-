#!/usr/bin/env node
/**
 * vuln_detect.js - Vulnerability Detection Module (Frame-Aware with Static Integration)
 * 
 * Analyzes EVM transaction traces to detect security vulnerabilities:
 * 1. Reentrancy patterns (frame-aware via callFrames)
 * 2. Arithmetic overflow/underflow:
 *    - Dynamic: Detects Solidity 0.8 Panic(0x11) in revert data
 *    - Fallback: Heuristic detection of arithmetic ops followed by REVERT/INVALID
 * 3. Unchecked external call returns
 * 4. Access control issues (tx.origin, dangerous delegatecalls)
 * 5. Static analysis integration (Slither/Mythril findings)
 * 
 * Uses callFrames/stepToFrameId from parsed_trace.json for frame-aware scope analysis.
 * Integrates slither.json and mythril.json if present in working directory.
 * 
 * Note: These are heuristics based on trace evidence and static analysis, NOT formal proofs.
 * For production, always review findings manually and combine with additional analysis.
 * 
 * Usage:
 *   node scripts/vuln_detect.js --parsed parsed_trace.json --trace trace.json --out findings.json
 */

const fs = require('fs');
const path = require('path');

// ====== Configuration ======
const MAX_WINDOW_STEPS = 200;  // Fallback window if frame mapping absent

// Mainnet/hardhat precompiles (chain 31337 uses same)
const PRECOMPILES = new Set([
  '0x0000000000000000000000000000000000000001',
  '0x0000000000000000000000000000000000000002',
  '0x0000000000000000000000000000000000000003',
  '0x0000000000000000000000000000000000000004',
  '0x0000000000000000000000000000000000000005',
  '0x0000000000000000000000000000000000000006',
  '0x0000000000000000000000000000000000000007',
  '0x0000000000000000000000000000000000000008',
  '0x0000000000000000000000000000000000000009'
]);

// ====== CLI Argument Parser ======
function parseArgs() {
  const args = process.argv.slice(2);
  const result = { parsed: 'parsed_trace.json', trace: null, out: 'findings.json' };
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--parsed' && args[i + 1]) result.parsed = args[i + 1];
    if (args[i] === '--trace' && args[i + 1]) result.trace = args[i + 1];
    if (args[i] === '--out' && args[i + 1]) result.out = args[i + 1];
  }
  return result;
}

// ====== Helper: Check if address is precompile or self ======
function isPrecompile(addr) {
  if (!addr) return false;
  const normalized = addr.toLowerCase();
  return PRECOMPILES.has(normalized);
}

// ====== Helper: Check if address is same as contract ======
function isSelfCall(addr, contractAddr) {
  if (!addr || !contractAddr) return false;
  return addr.toLowerCase() === contractAddr.toLowerCase();
}

// ====== Finding Generator ======
class VulnDetector {
  constructor(parsedData, traceData = null) {
    this.parsed = parsedData;
    this.trace = traceData;
    this.findings = [];
    this.id = 0;
    
    // Caches
    this.callFrames = parsedData.callFrames || [];
    this.stepToFrameId = parsedData.stepToFrameId || [];
    this.rows = parsedData.rows || [];
    this.sstores = parsedData.sstores || [];
  }

  addFinding(rule, severity, title, description, evidence, tags = []) {
    this.findings.push({
      id: `VUL-${String(++this.id).padStart(4, '0')}`,
      rule,
      severity,
      title,
      description,
      evidence,
      recommendation: this.getRecommendation(rule),
      tags
    });
  }

  getRecommendation(rule) {
    const recs = {
      'ReentrancyHeuristicFrame': 'Use checks-effects-interactions pattern. Emit events before external calls. Consider reentrancy guards (OpenZeppelin).',
      'reentrancy': 'Use checks-effects-interactions pattern. Emit events before external calls. Consider reentrancy guards (OpenZeppelin).',
      'unchecked_call': 'Always check return value of external calls. Use require() or handle failure cases explicitly.',
      'TxOriginAuthHeuristic': 'Never use tx.origin for access control. Use msg.sender instead. If tx.origin is necessary, validate against authenticated context.',
      'DelegatecallTargetHeuristic': 'Avoid delegatecall if possible. If necessary, ensure target address is a constant that is whitelisted and audited. Use access control patterns to restrict who can call delegatecall functions.',
      'ArithmeticOverflowUnderflow': 'Upgrade to Solidity >=0.8 for built-in overflow checks. For earlier versions, use SafeMath library. Ensure all arithmetic operations are properly bounded and validated.',
      'tx_origin': 'Never use tx.origin for access control. Use msg.sender instead.',
      'delegatecall': 'Avoid delegatecall or ensure target is whitelisted and safe. Document the intended behavior.',
      'overflow': 'Upgrade to Solidity >=0.8 for built-in overflow checks. Or use SafeMath library.',
      'underflow': 'Upgrade to Solidity >=0.8 for built-in overflow checks. Or use SafeMath library.'
    };
    return recs[rule] || 'Review this vulnerability and apply appropriate mitigations.';
  }

  // ====== Heuristic 1: Frame-Aware Reentrancy Detection ======
  detectReentrancyFrameAware() {
    // Requires callFrames and stepToFrameId from parsed_trace
    if (!this.callFrames || this.callFrames.length === 0 || !this.stepToFrameId || this.stepToFrameId.length === 0) {
      // Fall back to non-frame detection if not available
      this.detectReentrancyLegacy();
      return;
    }

    // Build a map: frameId -> list of {step, op, to, value, selector} for calls
    const frameCallsMap = new Map();
    const frameStoresMap = new Map(); // frameId -> list of {step, slot, value}
    const frameNestedMap = new Map(); // frameId -> list of nested frame ids

    // Scan rows for CALL/DELEGATECALL/STATICCALL/CALLCODE and SSTORE
    this.rows.forEach((row, idx) => {
      const frameId = this.stepToFrameId[idx];
      if (frameId === undefined) return;

      // Track CALL operations
      if (['CALL', 'DELEGATECALL', 'STATICCALL', 'CALLCODE'].includes(row.op)) {
        if (!frameCallsMap.has(frameId)) {
          frameCallsMap.set(frameId, []);
        }

        // Try to extract target from structLog if available
        let to = null;
        let value = null;
        let selector = null;
        if (this.trace && this.trace.result && this.trace.result.structLogs && this.trace.result.structLogs[idx - 1]) {
          const log = this.trace.result.structLogs[idx - 1];
          // Parse stack to get target (best effort)
          if (log.stack && log.stack.length > 0) {
            to = log.stack[log.stack.length - row.op === 'CALL' ? 6 : 5] || null;
            value = row.op === 'CALL' ? (log.stack[log.stack.length - 5] || null) : null;
            selector = log.stack[log.stack.length - 1] || null;
          }
        }

        frameCallsMap.get(frameId).push({
          step: row.step,
          op: row.op,
          to,
          value,
          selector,
          pc: row.pc
        });
      }

      // Track SSTORE operations
      if (row.isStorage && row.op === 'SSTORE') {
        if (!frameStoresMap.has(frameId)) {
          frameStoresMap.set(frameId, []);
        }
        
        // Find matching sstore entry by step
        const sstore = this.sstores.find(s => s.step === row.step);
        if (sstore) {
          frameStoresMap.get(frameId).push({
            step: row.step,
            slot: sstore.slot,
            value: sstore.value
          });
        }
      }
    });

    // Build frame nested children map
    this.callFrames.forEach((frame) => {
      if (frame.children && frame.children.length > 0) {
        frameNestedMap.set(frame.id, frame.children);
      }
    });

    // ====== Rule R1: External call + SSTORE in same frame + nested calls ======
    this.callFrames.forEach((frame) => {
      const calls = frameCallsMap.get(frame.id) || [];
      const stores = frameStoresMap.get(frame.id) || [];

      if (calls.length === 0 || stores.length === 0) return;

      // For each external call, check if there are sstores after it
      calls.forEach((callInfo) => {
        // Filter sstores that occur after this call
        const storesAfterCall = stores.filter(s => s.step > callInfo.step);

        if (storesAfterCall.length === 0) return;

        // Check if target is NOT a precompile and not self-call
        const isExternalCall = !(isPrecompile(callInfo.to) || isSelfCall(callInfo.to, frame.to));
        if (!isExternalCall && callInfo.op !== 'DELEGATECALL') return; // DELEGATECALL is always considered external

        // Check if frame has nested calls (children frames within depth+1)
        const hasNestedFrames = frame.children && frame.children.length > 0;

        if (hasNestedFrames || callInfo.op === 'DELEGATECALL') {
          this.addFinding(
            'ReentrancyHeuristicFrame',
            'high',
            'Potential Reentrancy: External Call Before State Update (Frame-Aware)',
            `Frame ${frame.id} (${frame.type}) contains external ${callInfo.op} at step ${callInfo.step} ` +
            `to ${callInfo.to || 'unknown'}, followed by state update(s) at steps ${storesAfterCall.map(s => s.step).join(', ')}. ` +
            `Attacker callback in nested frame(s) may exploit state inconsistency.`,
            {
              frameId: frame.id,
              frameType: frame.type,
              externalCall: {
                step: callInfo.step,
                op: callInfo.op,
                to: callInfo.to,
                value: callInfo.value,
                selector: callInfo.selector
              },
              nestedFrames: frame.children || [],
              sstores: storesAfterCall
            },
            ['reentrancy', 'frame-aware']
          );
        }
      });
    });

    // ====== Rule R2: Multiple writes to same slot after external call ======
    this.callFrames.forEach((frame) => {
      const calls = frameCallsMap.get(frame.id) || [];
      const stores = frameStoresMap.get(frame.id) || [];

      if (calls.length === 0 || stores.length < 2) return;

      calls.forEach((callInfo) => {
        const storesAfterCall = stores.filter(s => s.step > callInfo.step);

        // Find slots written more than once after this call
        const slotWriteCounts = new Map();
        storesAfterCall.forEach((store) => {
          const count = (slotWriteCounts.get(store.slot) || 0) + 1;
          slotWriteCounts.set(store.slot, count);
        });

        // Report slots with multiple writes
        slotWriteCounts.forEach((count, slot) => {
          if (count > 1) {
            const slotsWithMultipleWrites = storesAfterCall.filter(s => s.slot === slot);

            const isExternalCall = !(isPrecompile(callInfo.to) || isSelfCall(callInfo.to, frame.to));
            if (!isExternalCall && callInfo.op !== 'DELEGATECALL') return;

            this.addFinding(
              'ReentrancyHeuristicFrame',
              'medium',
              'Potential Reentrancy: Multiple State Updates After External Call',
              `Frame ${frame.id} writes to slot ${slot} ${count} times (steps ${slotsWithMultipleWrites.map(s => s.step).join(', ')}) ` +
              `after external ${callInfo.op} at step ${callInfo.step}. ` +
              `Multiple updates to same state in single frame after external interaction indicates race condition risk.`,
              {
                frameId: frame.id,
                frameType: frame.type,
                externalCall: {
                  step: callInfo.step,
                  op: callInfo.op,
                  to: callInfo.to,
                  value: callInfo.value
                },
                multipleWrites: {
                  slot,
                  count,
                  steps: slotsWithMultipleWrites.map(s => s.step)
                },
                sstores: slotsWithMultipleWrites
              },
              ['reentrancy', 'frame-aware', 'state-race']
            );
          }
        });
      });
    });
  }

  // ====== Fallback: Legacy Reentrancy Detection (non-frame-aware) ======
  detectReentrancyLegacy() {
    if (!this.rows) return;

    const callDepths = [];
    let maxDepth = 0;

    // Track CALL/DELEGATECALL operations and depth changes
    this.rows.forEach((row, idx) => {
      if (row.isCall) {
        callDepths.push({ step: idx, op: row.op, depth: row.depth });
        maxDepth = Math.max(maxDepth, row.depth);
      }
      if (row.isStorage) {
        callDepths.push({ step: idx, op: 'SSTORE', depth: row.depth });
      }
    });

    if (callDepths.length < 2) return;

    for (let i = 0; i < callDepths.length - 1; i++) {
      const current = callDepths[i];
      const next = callDepths[i + 1];

      if (current.op.includes('CALL') && next.op === 'SSTORE' && 
          next.depth <= current.depth && next.step - current.step < MAX_WINDOW_STEPS) {
        
        const evidence = {
          pattern: 'state_update_after_external_call (legacy)',
          call_step: current.step,
          call_op: current.op,
          call_depth: current.depth,
          sstore_step: next.step,
          sstore_depth: next.depth,
          steps_between: next.step - current.step
        };

        this.addFinding(
          'reentrancy',
          'high',
          'Potential Reentrancy: External Call Before State Update (legacy)',
          `External call at step ${current.step} (${current.op}) followed by state update (SSTORE) at step ${next.step}. ` +
          'Attacker callback may exploit state inconsistency. (No frame data available; using legacy detection.)',
          evidence,
          ['reentrancy', 'legacy']
        );
        break;
      }
    }
  }

  // ====== Heuristic 2: Unchecked External Call Detection ======
  detectUncheckedCalls() {
    if (!this.rows) return;

    const callOps = ['CALL', 'STATICCALL', 'DELEGATECALL', 'CALLCODE'];

    this.rows.forEach((row, idx) => {
      if (!callOps.includes(row.op)) return;

      let foundCheck = false;
      for (let i = idx + 1; i < Math.min(idx + 20, this.rows.length); i++) {
        const nextOp = this.rows[i].op;
        if (['ISZERO', 'REVERT', 'JUMPI', 'REQUIRE'].includes(nextOp)) {
          foundCheck = true;
          break;
        }
      }

      if (!foundCheck) {
        const evidence = {
          call_step: row.step,
          call_op: row.op,
          pc: row.pc,
          checked_within_steps: 20,
          found_check: false
        };

        this.addFinding(
          'unchecked_call',
          'medium',
          `Unchecked External Call: ${row.op}`,
          `External call (${row.op}) at step ${row.step} has no apparent return value check ` +
          'in the following 20 steps. Call may fail silently.',
          evidence,
          ['unchecked-call']
        );
      }
    });
  }

  // ====== Heuristic 3: Improved Access Control Issues ======
  
  /**
   * Helper: Extract address from stack value
   */
  extractAddressFromStack(stackValue) {
    if (!stackValue) return null;
    const hex = stackValue.replace('0x', '').toLowerCase();
    if (hex.length < 40) return null;
    return '0x' + hex.slice(-40);
  }

  /**
   * Helper: Check if PUSH20 with target address occurred within previous M steps
   */
  checkPUSH20Preceding(targetAddr, startStep, frameId, maxSteps = 10) {
    if (!targetAddr) return false;

    const targetNorm = targetAddr.toLowerCase();
    const checkFrom = Math.max(0, startStep - maxSteps);

    for (let i = checkFrom; i < startStep; i++) {
      const row = this.rows[i];
      if (!row) continue;

      // Check if step is in same frame
      if (this.stepToFrameId[i] !== frameId) continue;

      // Check for PUSH20 opcode
      if (row.op === 'PUSH20') {
        // Try to extract value from trace if available
        if (this.trace && this.trace.result && this.trace.result.structLogs && this.trace.result.structLogs[i - 1]) {
          const log = this.trace.result.structLogs[i - 1];
          if (log.stack && log.stack.length > 0) {
            const stackTop = log.stack[log.stack.length - 1] || '';
            const pushed = this.extractAddressFromStack(stackTop);
            if (pushed && pushed.toLowerCase() === targetNorm) {
              return true;
            }
          }
        }
      }
    }
    return false;
  }

  /**
   * Helper: Find nearby branch/revert operations within N steps
   */
  findNearbyControl(originStep, frameId, maxSteps = 50) {
    const nearby = [];
    const checkThrough = Math.min(originStep + maxSteps, this.rows.length);

    for (let i = originStep + 1; i < checkThrough; i++) {
      const row = this.rows[i];
      if (!row) continue;

      // Check if step is in same frame
      if (this.stepToFrameId[i] !== frameId) continue;

      if (['JUMPI', 'REVERT', 'REQUIRE'].includes(row.op)) {
        nearby.push({ step: row.step, op: row.op, pc: row.pc });
        if (nearby.length >= 3) break; // Limit results
      }
    }

    return nearby;
  }

  /**
   * Helper: Extract target address from DELEGATECALL stack
   * DELEGATECALL stack (before opcode): [..., gas, to, inOffset, inSize, outOffset, outSize]
   * Stack index: [outSize(0), outOffset(1), inSize(2), inOffset(3), to(4), gas(5), ...]
   */
  extractDelegatecallTarget(rowIndex) {
    if (!this.trace || !this.trace.result || !this.trace.result.structLogs) {
      return null;
    }

    const structLog = this.trace.result.structLogs[rowIndex - 1];
    if (!structLog || !structLog.stack || structLog.stack.length < 6) {
      return null;
    }

    // Stack index 4 from top is the 'to' address for DELEGATECALL
    const targetStack = structLog.stack[structLog.stack.length - 5];
    return this.extractAddressFromStack(targetStack);
  }

  /**
   * Helper: Extract selector from calldata (first 4 bytes when stored as hex string)
   */
  extractSelector(calldata) {
    if (!calldata || calldata.length < 10) return null;
    return calldata.substring(0, 10);
  }

  detectAccessControl() {
    if (!this.rows || this.rows.length === 0) return;

    // ====== Rule: TxOriginAuthHeuristic ======
    const originUsages = this.rows.filter(row => row.op === 'ORIGIN');

    originUsages.forEach((originRow, idx) => {
      const frameId = this.stepToFrameId[originRow.step - 1];
      const nearbyOps = this.findNearbyControl(originRow.step - 1, frameId, 50);

      let severity = 'low';
      if (nearbyOps.length > 0) {
        // If ORIGIN is near JUMPI/REVERT, likely used in auth check
        severity = 'medium';
      }

      const evidence = {
        step: originRow.step,
        pc: originRow.pc,
        frameId,
        nearbyControls: nearbyOps.length > 0 ? nearbyOps.slice(0, 2) : []
      };

      this.addFinding(
        'TxOriginAuthHeuristic',
        severity,
        'Use of tx.origin in Access Control Logic',
        `ORIGIN opcode detected at step ${originRow.step} in frame ${frameId}. ` +
        (nearbyOps.length > 0
          ? `Found nearby control flow ops (${nearbyOps.map(o => o.op).join(', ')}) suggesting auth check. `
          : ``) +
        'Using tx.origin for access control is dangerous as it can be exploited in delegatecall chains and cross-contract transactions.',
        evidence,
        ['access-control', 'tx-origin']
      );
    });

    // ====== Rule: DelegatecallTargetHeuristic ======
    const delegatecalls = this.rows.filter(row => row.op === 'DELEGATECALL');

    delegatecalls.forEach((dcRow, idx) => {
      const frameId = this.stepToFrameId[dcRow.step - 1];
      const targetAddr = this.extractDelegatecallTarget(dcRow.step - 1);
      const isConstTarget = targetAddr && this.checkPUSH20Preceding(targetAddr, dcRow.step - 1, frameId, 10);

      // Lower severity if target appears to be constant (from PUSH20)
      let severity = 'high';
      if (isConstTarget) {
        severity = 'medium';
      }

      const evidence = {
        step: dcRow.step,
        pc: dcRow.pc,
        frameId,
        targetAddress: targetAddr || 'unknown',
        targetIsConstant: isConstTarget,
        precededByPUSH20: isConstTarget
      };

      this.addFinding(
        'DelegatecallTargetHeuristic',
        severity,
        'Risky DELEGATECALL: Execution Control Risk',
        `DELEGATECALL at step ${dcRow.step} in frame ${frameId} targets ${targetAddr || 'dynamic address'}. ` +
        (isConstTarget
          ? 'Target appears to be hardcoded (constant), reducing risk. '
          : 'Target address appears to be dynamic or unverified. ') +
        'DELEGATECALL executes target code in caller context, risking unauthorized state changes and reentrancy. ' +
        'Ensure target is whitelisted and audited.',
        evidence,
        ['delegatecall', 'execution-control']
      );
    });
  }

  // ====== Heuristic 4: Refined Overflow/Underflow Detection with Panic Decoding ======

  /**
   * Helper: Extract memory range from structLog memory array
   * @param {number} memOffset - Byte offset in memory
   * @param {number} memSize - Number of bytes to extract
   * @param {Array} memoryWords - Memory array (32-byte hex strings)
   * @returns {string} Hex string (0x...)
   */
  extractMemoryRange(memOffset, memSize, memoryWords) {
    if (!memoryWords || memoryWords.length === 0 || memSize === 0) {
      return null;
    }

    try {
      let result = '';
      const memoryBytes = [];

      // Flatten memory words to bytes
      for (const word of memoryWords) {
        const hex = word.replace('0x', '').padStart(64, '0');
        for (let j = 0; j < 32; j++) {
          memoryBytes.push(hex.substring(j * 2, j * 2 + 2));
        }
      }

      // Extract bytes from offset to offset+size
      for (let i = memOffset; i < memOffset + memSize && i < memoryBytes.length; i++) {
        result += memoryBytes[i];
      }

      return result.length > 0 ? '0x' + result : null;
    } catch (err) {
      return null;
    }
  }

  /**
   * Helper: Decode Panic(uint256) from revert data
   * Panic selector: 0x4e487b71 (4 bytes)
   * Panic code: uint256 (32 bytes)
   * @param {string} revertData - Full revert data hex string (0x...)
   * @returns {Object|null} {selector: 0x..., code: number} or null
   */
  decodePanicRevert(revertData) {
    if (!revertData || revertData.length < 10) {
      return null;
    }

    const selector = revertData.substring(0, 10).toLowerCase();
    const PANIC_SELECTOR = '0x4e487b71';

    if (selector !== PANIC_SELECTOR) {
      return null;
    }

    // Extract code (offset 4, length 32)
    if (revertData.length < 10 + 64) {
      return null;
    }

    const codeHex = revertData.substring(10, 10 + 64);
    try {
      const code = parseInt(codeHex, 16);
      return { selector, code };
    } catch (err) {
      return null;
    }
  }

  /**
   * Helper: Find preceding arithmetic operations in same frame
   * @param {number} revertStep - Step index of REVERT opcode
   * @param {number} frameId - Frame ID to search within
   * @param {number} lookBack - Max steps to look back (default 30)
   * @returns {Array} List of {step, op, pc}
   */
  findPrecedingArithmetic(revertStep, frameId, lookBack = 30) {
    const arithmetic = [];
    const startStep = Math.max(0, revertStep - lookBack);

    for (let i = startStep; i < revertStep; i++) {
      const row = this.rows[i];
      if (!row) continue;

      // Check if step is in same frame
      if (this.stepToFrameId[i] !== frameId) continue;

      if (['ADD', 'SUB', 'MUL', 'DIV'].includes(row.op)) {
        arithmetic.push({ step: row.step, op: row.op, pc: row.pc });
      }
    }

    return arithmetic;
  }

  /**
   * Main: Detect overflow/underflow via Panic(0x11) or heuristics
   */
  detectOverflow() {
    if (!this.rows || this.rows.length === 0) return;

    // ====== Dynamic: Panic(0x11) Detection ======
    const revertRows = this.rows.filter(row => row.op === 'REVERT');

    revertRows.forEach((revertRow, idx) => {
      const frameId = this.stepToFrameId[revertRow.step - 1];
      let panicInfo = null;

      // Try to extract revert data from memory
      if (this.trace && this.trace.result && this.trace.result.structLogs && this.trace.result.structLogs[revertRow.step - 1]) {
        const structLog = this.trace.result.structLogs[revertRow.step - 1];
        const stack = structLog.stack || [];
        const memory = structLog.memory || [];

        // REVERT opcode: stack[offset, size]
        if (stack.length >= 2) {
          try {
            const offsetHex = stack[stack.length - 1];
            const sizeHex = stack[stack.length - 2];
            const offset = parseInt(offsetHex, 16);
            const size = parseInt(sizeHex, 16);

            if (offset >= 0 && size > 0 && size <= 200) { // Reasonable bounds
              const revertData = this.extractMemoryRange(offset, size, memory);
              if (revertData) {
                panicInfo = this.decodePanicRevert(revertData);
              }
            }
          } catch (err) {
            // Failed to parse stack values, continue
          }
        }
      }

      // If panic(0x11) detected, emit high-confidence finding
      if (panicInfo && panicInfo.code === 0x11) {
        const precedingOps = this.findPrecedingArithmetic(revertRow.step - 1, frameId, 30);

        const evidence = {
          revert_step: revertRow.step,
          panic_selector: panicInfo.selector,
          panic_code: panicInfo.code,
          panic_code_meaning: 'Arithmetic Overflow/Underflow',
          frameId,
          preceding_arithmetic_ops: precedingOps.slice(0, 5)
        };

        this.addFinding(
          'ArithmeticOverflowUnderflow',
          'high',
          'Arithmetic Overflow/Underflow Panic Detected',
          `Solidity 0.8 panic detected at step ${revertRow.step} with selector ${panicInfo.selector} ` +
          `and code 0x${panicInfo.code.toString(16)} (arithmetic overflow/underflow). ` +
          `The transaction reverted due to arithmetic operation exceeding valid range. ` +
          (precedingOps.length > 0
            ? `Found ${precedingOps.length} arithmetic operations (${precedingOps.map(o => o.op).join(', ')}) in preceding ${Math.min(30, revertRow.step - 1)} steps.`
            : `No preceding arithmetic operations detected in lookback window.`),
          evidence,
          ['dynamic', 'overflow', 'panic-detected']
        );
        return; // Once panic detected, skip fallback heuristic
      }
    });

    // ====== Dynamic Fallback: Heuristic Detection ======
    const arithmeticOps = ['ADD', 'SUB', 'MUL', 'DIV'];

    this.rows.forEach((row, idx) => {
      if (!arithmeticOps.includes(row.op)) return;

      for (let i = idx + 1; i < Math.min(idx + 5, this.rows.length); i++) {
        const nextOp = this.rows[i].op;
        if (nextOp === 'INVALID' || nextOp === 'REVERT') {
          const evidence = {
            arithmetic_step: row.step,
            arithmetic_op: row.op,
            failure_step: this.rows[i].step,
            failure_op: nextOp,
            steps_between: this.rows[i].step - row.step
          };

          this.addFinding(
            'ArithmeticOverflowUnderflow',
            'medium',
            `Possible ${row.op} Overflow/Underflow (Heuristic)`,
            `Arithmetic operation (${row.op}) at step ${row.step} followed by ${nextOp} at step ${this.rows[i].step}. ` +
            'May indicate overflow check in Solidity >=0.8 or SafeMath library. No Panic selector confirmed.',
            evidence,
            ['dynamic', 'overflow', 'heuristic']
          );
          break;
        }
      }
    });
  }

  /**
   * Integrate static analysis results from Slither/Mythril if available
   */
  integrateStaticAnalysis() {
    const workingDir = process.cwd();

    // Check for Slither results
    const slitherPath = path.join(workingDir, 'slither.json');
    if (fs.existsSync(slitherPath)) {
      try {
        const slitherData = JSON.parse(fs.readFileSync(slitherPath, 'utf-8'));
        
        // Parse for arithmetic-related issues
        if (slitherData.results && Array.isArray(slitherData.results)) {
          slitherData.results.forEach((result) => {
            // Check for arithmetic-related detector names
            if (result.check && (result.check.includes('arithmetic') || result.check.includes('overflow') || result.check.includes('underflow'))) {
              const severity = this.mapSlitherSeverity(result.impact);
              const evidence = {
                source: 'Slither',
                check: result.check,
                impact: result.impact,
                description: result.description || ''
              };

              this.addFinding(
                'ArithmeticOverflowUnderflow',
                severity,
                `Slither: ${result.check}`,
                result.description || `Static analysis detected potential arithmetic issue: ${result.check}`,
                evidence,
                ['static', 'overflow', 'slither']
              );
            }
          });
        }
      } catch (err) {
        console.warn(`⚠ Failed to parse slither.json: ${err.message}`);
      }
    }

    // Check for Mythril results
    const mythrilPath = path.join(workingDir, 'mythril.json');
    if (fs.existsSync(mythrilPath)) {
      try {
        const mythrilData = JSON.parse(fs.readFileSync(mythrilPath, 'utf-8'));

        // Mythril issues array
        if (mythrilData.issues && Array.isArray(mythrilData.issues)) {
          mythrilData.issues.forEach((issue) => {
            // Check for arithmetic-related issues
            if (issue.title && (issue.title.includes('arithmetic') || issue.title.includes('overflow') || issue.title.includes('underflow'))) {
              const severity = this.mapMythrilSeverity(issue.severity);
              const evidence = {
                source: 'Mythril',
                title: issue.title,
                severity: issue.severity,
                description: issue.description || ''
              };

              this.addFinding(
                'ArithmeticOverflowUnderflow',
                severity,
                `Mythril: ${issue.title}`,
                issue.description || `Static analysis detected potential arithmetic issue: ${issue.title}`,
                evidence,
                ['static', 'overflow', 'mythril']
              );
            }
          });
        }
      } catch (err) {
        console.warn(`⚠ Failed to parse mythril.json: ${err.message}`);
      }
    }
  }

  /**
   * Helper: Map Slither severity to our severity levels
   */
  mapSlitherSeverity(impact) {
    const severityMap = {
      'high': 'high',
      'medium': 'medium',
      'low': 'low',
      'informational': 'low'
    };
    return severityMap[impact] || 'medium';
  }

  /**
   * Helper: Map Mythril severity to our severity levels
   */
  mapMythrilSeverity(severity) {
    const severityMap = {
      'High': 'high',
      'Medium': 'medium',
      'Low': 'low',
      'Informational': 'low'
    };
    return severityMap[severity] || 'medium';
  }

  // ====== Run All Detectors ======
  analyze() {
    // Use frame-aware reentrancy (falls back to legacy if frame data absent)
    this.detectReentrancyFrameAware();
    this.detectUncheckedCalls();
    this.detectAccessControl();
    this.detectOverflow();
    
    // Integrate static analysis results
    this.integrateStaticAnalysis();
    
    return this.findings;
  }
}

// ====== Main Entry Point ======
async function main() {
  const args = parseArgs();
  
  if (!fs.existsSync(args.parsed)) {
    console.error(`❌ parsed_trace.json not found at ${args.parsed}`);
    process.exit(1);
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(args.parsed, 'utf-8'));
    
    let traceData = null;
    if (args.trace && fs.existsSync(args.trace)) {
      traceData = JSON.parse(fs.readFileSync(args.trace, 'utf-8'));
    }

    const detector = new VulnDetector(parsed, traceData);
    const findings = detector.analyze();

    const output = {
      findings,
      summary: {
        total: findings.length,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
      }
    };

    fs.writeFileSync(args.out, JSON.stringify(output, null, 2));
    
    console.log(`✓ Vulnerability detection completed`);
    console.log(`  Total findings: ${findings.length}`);
    console.log(`  Critical: ${output.summary.critical}, High: ${output.summary.high}, Medium: ${output.summary.medium}, Low: ${output.summary.low}`);
    console.log(`  Output: ${args.out}`);
    
    // Note about frame data
    if (findings.some(f => f.rule === 'ReentrancyHeuristicFrame')) {
      console.log(`  Using frame-aware reentrancy detection (callFrames present)`);
    } else if (findings.some(f => f.tags && f.tags.includes('legacy'))) {
      console.log(`  ⚠ Using legacy reentrancy detection (callFrames not found; run parse_trace.js first)`);
    }

  } catch (err) {
    console.error('❌ Error during vulnerability detection:', err.message);
    process.exit(1);
  }
}

main();
