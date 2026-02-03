const fs = require('fs');
const path = require('path');

function hexToDecimal(hexString) {
  const cleanHex = hexString.startsWith('0x') ? hexString.slice(2) : hexString;
  return BigInt(`0x${cleanHex}`).toString(10);
}

function normalizeSlot(slot) {
  const cleanSlot = slot.startsWith('0x') ? slot.slice(2) : slot;
  return cleanSlot.padStart(64, '0');
}

function generateStateDiff() {
  try {
    const traceFilePath = path.join(__dirname, 'parsed_trace.json');
    
    if (!fs.existsSync(traceFilePath)) {
      throw new Error(`File not found: ${traceFilePath}`);
    }

    const traceData = JSON.parse(fs.readFileSync(traceFilePath, 'utf-8'));

    if (!traceData.sstores || !Array.isArray(traceData.sstores)) {
      throw new Error('sstores attribute not found or is not an array');
    }

    const sstoreRecords = traceData.sstores.filter(record => record.op === 'SSTORE');

    if (sstoreRecords.length === 0) {
      throw new Error('No SSTORE operation records found');
    }

    console.log(`✓ Found ${sstoreRecords.length} SSTORE records`);

    const slot0Records = sstoreRecords.filter(record => {
      const slot = normalizeSlot(record.stackTop);
      const zeroSlot = '0000000000000000000000000000000000000000000000000000000000000000';
      return slot === zeroSlot;
    });

    if (slot0Records.length === 0) {
      throw new Error('No SSTORE records found for slot=0');
    }

    console.log(`✓ Found ${slot0Records.length} SSTORE records with slot=0`);

    const latestSlot0Record = slot0Records[slot0Records.length - 1];
    const afterHex = latestSlot0Record.stackTop3[0];
    const afterDecimal = hexToDecimal(afterHex);
    const beforeDecimal = '0';
    const diffMessage = `Storage Diff for Demo.sol (slot=0): Before=${beforeDecimal} | After=${afterDecimal}`;
    
    console.log(`\n✓ ${diffMessage}`);

    const mdContent = generateMarkdownReport(diffMessage, sstoreRecords, slot0Records, latestSlot0Record);

    const docsDir = path.join(__dirname, 'docs');
    if (!fs.existsSync(docsDir)) {
      fs.mkdirSync(docsDir, { recursive: true });
      console.log(`✓ Created directory: ${docsDir}`);
    }

    const mdFilePath = path.join(docsDir, 'state-diff.md');
    fs.writeFileSync(mdFilePath, mdContent, 'utf-8');
    console.log(`✓ Results saved to: ${mdFilePath}\n`);

  } catch (error) {
    console.error(`❌ Error: ${error.message}`);
    process.exit(1);
  }
}

function generateMarkdownReport(diffMessage, allRecords, slot0Records, latestRecord) {
  const timestamp = new Date().toISOString();
  const afterHex = latestRecord.stackTop3[0];
  const afterDecimal = hexToDecimal(afterHex);

  return `# Storage Diff Report - Demo.sol

## Execution Result

${diffMessage}

**Generated**: ${timestamp}

---

## Summary

- **Total SSTORE Operations**: ${allRecords.length}
- **SSTORE Operations at slot=0**: ${slot0Records.length}
- **Last Write (slot=0)**:
  - **Step**: ${latestRecord.step}
  - **PC**: ${latestRecord.pc}
  - **Gas**: ${latestRecord.gas}
  - **Gas Cost**: ${latestRecord.gasCost}

### Storage Change

| Property | Value |
|----------|-------|
| **Slot** | \`0\` |
| **Before (Dec)** | \`0\` |
| **After (Hex)** | \`${afterHex}\` |
| **After (Dec)** | \`${afterDecimal}\` |

---

For detailed analysis, implementation logic, limitations, and improvement directions, see [state-diff.md](state-diff.md) in the docs folder.
`;
}

generateStateDiff();
