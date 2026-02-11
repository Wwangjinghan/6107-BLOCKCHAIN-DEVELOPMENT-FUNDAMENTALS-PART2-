const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
const { execSync } = require('child_process');
const { buildCallFrames } = require('./call_frames');
const { mergeFindings } = require('./merge_findings');

// ====== 配置 ======
const RPC_URL = "http://127.0.0.1:8545";
const provider = new ethers.JsonRpcProvider(RPC_URL);

// ERC20 Transfer 事件 topic
const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

// ====== CLI Arguments ======
function parseArgs() {
  const args = process.argv.slice(2);
  const result = {
    detectVulns: args.includes('--detect-vulns'),
    embedFindings: args.includes('--embed-findings'),
    staticScan: args.includes('--static-scan'),
    findingsOut: null
  };

  // Parse --findings-out <path>
  const findingsOutIdx = args.indexOf('--findings-out');
  if (findingsOutIdx !== -1 && findingsOutIdx + 1 < args.length) {
    result.findingsOut = args[findingsOutIdx + 1];
  }

  return result;
}

// ====== 工具函数 ======
function normalizeSlot(slot) {
  if (!slot) return ''.padStart(64, '0');
  const clean = slot.startsWith('0x') ? slot.slice(2) : slot;
  return clean.padStart(64, '0');
}

// Run vulnerability detection on parsed trace
function runVulnDetection(parsedFile) {
  try {
    const vulnScript = path.join(__dirname, 'vuln_detect.js');
    const findingsFile = path.join(__dirname, '../findings.json');
    
    const cmd = `node ${vulnScript} --parsed ${parsedFile} --out ${findingsFile}`;
    execSync(cmd, { stdio: 'inherit' });
    
    // Load findings if they were generated
    if (fs.existsSync(findingsFile)) {
      const findings = JSON.parse(fs.readFileSync(findingsFile, 'utf-8'));
      return findings;
    }
  } catch (err) {
    console.warn('⚠ Vulnerability detection failed:', err.message);
  }
  return null;
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
  // Call Frame Reconstruction
  // ======================
  const txMeta = {
    from: tx.from,
    to: tx.to || null,
    input: tx.data || null,
    value: tx.value.toString()
  };

  const { frames: callFrames, stepToFrameId } = buildCallFrames(structLogs, txMeta);

  // ======================
  // 最终输出
  // ======================
  const output = {
    rows,
    topOps,
    sstores,
    storageDiff,
    transfers,
    balanceChanges,
    callFrames,
    stepToFrameId
  };

  fs.writeFileSync(outFile, JSON.stringify(output, null, 2));

  console.log("✓ parsed_trace.json generated");
  
  // ====== Optional: Run Vulnerability Detection & Static Analysis ======
  const cliArgs = parseArgs();
  
  if (cliArgs.detectVulns || cliArgs.staticScan || cliArgs.findingsOut) {
    console.log("\n🔍 Running vulnerability detection and analysis...");
    
    let dynamicFindings = null;
    let slitherData = null;
    let mythrilData = null;
    
    // Run dynamic vulnerability detection
    if (cliArgs.detectVulns) {
      console.log("  - Dynamic analysis (trace-based)...");
      const vulnResult = runVulnDetection(outFile);
      dynamicFindings = vulnResult ? vulnResult.findings : [];
    } else {
      dynamicFindings = [];
    }
    
    // Run static analysis if requested
    if (cliArgs.staticScan) {
      console.log("  - Static analysis (Slither/Mythril)...");
      const staticResult = runStaticScan();
      slitherData = staticResult.slither;
      mythrilData = staticResult.mythril;
    }
    
    // Merge findings
    const mergedFindings = mergeFindings(dynamicFindings, slitherData, mythrilData);
    
    const findingsSummary = {
      total: mergedFindings.length,
      critical: mergedFindings.filter(f => f.severity === 'critical').length,
      high: mergedFindings.filter(f => f.severity === 'high').length,
      medium: mergedFindings.filter(f => f.severity === 'medium').length,
      low: mergedFindings.filter(f => f.severity === 'low').length
    };
    
    // Output merged findings to separate file if specified
    if (cliArgs.findingsOut) {
      const findingsOutput = {
        findings: mergedFindings,
        summary: findingsSummary
      };
      fs.writeFileSync(cliArgs.findingsOut, JSON.stringify(findingsOutput, null, 2));
      console.log(`✓ Merged findings written to ${cliArgs.findingsOut}`);
      console.log(`  Total: ${findingsSummary.total} (Critical: ${findingsSummary.critical}, High: ${findingsSummary.high}, Medium: ${findingsSummary.medium}, Low: ${findingsSummary.low})`);
    }
    
    // Embed findings in parsed trace if requested
    if (cliArgs.embedFindings) {
      output.findings = mergedFindings;
      output.vulnSummary = findingsSummary;
      fs.writeFileSync(outFile, JSON.stringify(output, null, 2));
      console.log(`✓ ${mergedFindings.length} merged findings embedded in parsed_trace.json`);
    }
  }
}

/**
 * Run static analysis (Slither and Mythril)
 * @returns {Object} {slither: data, mythril: data} - null if tools not available
 */
function runStaticScan() {
  const result = { slither: null, mythril: null };
  
  // Try Slither
  try {
    const slitherScript = path.join(__dirname, 'static_scan.js');
    if (fs.existsSync(slitherScript)) {
      try {
        console.log("    - Running Slither...");
        execSync(`node ${slitherScript} --tool slither`, { stdio: 'pipe' });
        
        // Try to read output
        const slitherPath = path.join(process.cwd(), 'slither.json');
        if (fs.existsSync(slitherPath)) {
          result.slither = JSON.parse(fs.readFileSync(slitherPath, 'utf-8'));
          console.log("    ✓ Slither analysis complete");
        }
      } catch (err) {
        console.warn(`    ⚠ Slither not available or failed: ${err.message}`);
      }
    }
  } catch (err) {
    console.warn(`    ⚠ Slither skipped: ${err.message}`);
  }
  
  // Try Mythril
  try {
    const staticScript = path.join(__dirname, 'static_scan.js');
    if (fs.existsSync(staticScript)) {
      try {
        console.log("    - Running Mythril...");
        execSync(`node ${staticScript} --tool mythril`, { stdio: 'pipe' });
        
        // Try to read output
        const mythrilPath = path.join(process.cwd(), 'mythril.json');
        if (fs.existsSync(mythrilPath)) {
          result.mythril = JSON.parse(fs.readFileSync(mythrilPath, 'utf-8'));
          console.log("    ✓ Mythril analysis complete");
        }
      } catch (err) {
        console.warn(`    ⚠ Mythril not available or failed: ${err.message}`);
      }
    }
  } catch (err) {
    console.warn(`    ⚠ Mythril skipped: ${err.message}`);
  }
  
  return result;
}

parseTrace();

