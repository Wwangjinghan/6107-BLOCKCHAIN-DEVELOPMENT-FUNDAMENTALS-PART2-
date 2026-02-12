const fs = require('fs');
const path = require('path');

// 将十六进制字符串转换为十进制
function hexToDecimal(hex) {
    if (!hex) return '0';
    const cleanHex = hex.startsWith('0x') ? hex : '0x' + hex;
    return BigInt(cleanHex).toString(10);
}

// 格式化 slot 为 64 位十六进制
function normalizeSlot(slot) {
    const clean = slot?.startsWith('0x') ? slot.slice(2) : slot ?? '';
    return clean.padStart(64, '0');
}

// 示例 slot -> name 映射，可根据实际合约扩展
const STORAGE_NAMES = {
    '0000000000000000000000000000000000000000000000000000000000000000': 'slot0',
    '0000000000000000000000000000000000000000000000000000000000000001': 'slot1',
};

// 主函数
function generateStateDiff() {
    try {
        const traceFilePath = path.join(__dirname, 'parsed_trace.json');
        if (!fs.existsSync(traceFilePath)) throw new Error(`File not found: ${traceFilePath}`);

        const traceData = JSON.parse(fs.readFileSync(traceFilePath, 'utf-8'));
        const rows = traceData.rows || [];

        if (rows.length === 0) throw new Error('No rows found in parsed_trace.json');

        // 过滤 SSTORE
        const sstoreRecords = rows.filter(r => r.op === 'SSTORE');
        if (sstoreRecords.length === 0) console.warn('⚠ No SSTORE operations found');

        // slot=0 专用统计
        const slot0Records = sstoreRecords.filter(record => {
            const slot = record.storageSlotName || normalizeSlot(record.stackTop ?? '0x0');
            return slot === '0000000000000000000000000000000000000000000000000000000000000000';
        });

        const latestSlot0Record = slot0Records[slot0Records.length - 1] || null;
        const afterHex = latestSlot0Record?.stackTop3?.[0] ?? '0x0';
        const afterDecimal = hexToDecimal(afterHex);
        const diffMessage = latestSlot0Record
            ? `Storage Diff for Demo.sol (slot=0): Before=0 | After=${afterDecimal}`
            : 'No slot=0 SSTORE writes found';

        console.log(`✓ Found ${sstoreRecords.length} SSTORE records`);
        console.log(`✓ Found ${slot0Records.length} SSTORE records with slot=0`);
        console.log(`\n✓ ${diffMessage}`);

        // 生成 Markdown
        const mdContent = generateMarkdownReport(diffMessage, sstoreRecords, slot0Records, latestSlot0Record, rows);

        // 输出到 docs
        const docsDir = path.join(__dirname, 'docs');
        if (!fs.existsSync(docsDir)) fs.mkdirSync(docsDir, { recursive: true });

        const mdFilePath = path.join(docsDir, 'state-diff.md');
        fs.writeFileSync(mdFilePath, mdContent, 'utf-8');
        console.log(`✓ Results saved to: ${mdFilePath}\n`);
    } catch (error) {
        console.error(`❌ Error: ${error.message}`);
        process.exit(1);
    }
}

// 生成 Markdown 内容
function generateMarkdownReport(diffMessage, allRecords, slot0Records, latestRecord, allRows) {
    const timestamp = new Date().toISOString();
    const afterHex = latestRecord?.stackTop3?.[0] ?? '0x0';
    const afterDecimal = hexToDecimal(afterHex);

    // 全部 SSTORE diff
    const storageDiffRows = [];
    const prevStorage = {};
    allRows.forEach(row => {
        if (!row.isStorage) return;
        const slot = row.storageSlotName || normalizeSlot(row.stackTop ?? '0x0');
        const oldVal = prevStorage[slot] ?? '0x0';
        const newVal = row.stackTop ?? oldVal;
        if (oldVal !== newVal) {
            storageDiffRows.push(`| ${row.step} | ${slot} | ${oldVal} | ${newVal} | ${row.op} |`);
            prevStorage[slot] = newVal;
        }
    });

    return `# Storage Diff Report - Demo.sol

## Execution Result

${diffMessage}

**Generated**: ${timestamp}

---

## Summary

- **Total SSTORE Operations**: ${allRecords.length}
- **SSTORE Operations at slot=0**: ${slot0Records.length}
- **Last Write (slot=0)**:
  - **Step**: ${latestRecord?.step ?? '-'}
  - **PC**: ${latestRecord?.pc ?? '-'}
  - **Gas**: ${latestRecord?.gas ?? '-'}
  - **Gas Cost**: ${latestRecord?.gasCost ?? '-'}

### Storage Change (slot=0)

| Property | Value |
|----------|-------|
| **Slot** | \`0\` |
| **Before (Dec)** | \`0\` |
| **After (Hex)** | \`${afterHex}\` |
| **After (Dec)** | \`${afterDecimal}\` |

### All SSTORE Changes

| Step | Slot | Old Value | New Value | Op |
|------|------|-----------|-----------|----|
${storageDiffRows.join('\n')}

---

For detailed analysis, implementation logic, limitations, and improvement directions, see [state-diff.md](state-diff.md) in the docs folder.
`;
}

// 执行
generateStateDiff();
