const fs = require('fs');
const path = require('path');

function hexToDecimal(hex) {
    if (!hex) return '0';
    return BigInt(hex).toString(10);
}

function normalizeSlot(slot) {
    const clean = slot?.startsWith('0x') ? slot.slice(2) : slot ?? '';
    return clean.padStart(64, '0');
}

// 示例 slot -> name 映射，可根据实际合约扩展
const STORAGE_NAMES = {
    '0000000000000000000000000000000000000000000000000000000000000000': 'slot0',
    '0000000000000000000000000000000000000000000000000000000000000001': 'slot1',
};

function parseTrace() {
    const traceFile = path.join(__dirname, '../trace.json');
    const outFile = path.join(__dirname, '../parsed_trace.json');

    if (!fs.existsSync(traceFile)) {
        console.error('❌ trace.json not found!');
        process.exit(1);
    }

    const trace = JSON.parse(fs.readFileSync(traceFile, 'utf-8'));
    const structLogs = trace.tx?.structLogs || [];

    const rows = [];
    const opCounts = {};

    structLogs.forEach((log, index) => {
        const op = log.op;
        opCounts[op] = (opCounts[op] || 0) + 1;

        // gasCost 默认 0
        const gasCost = log.gasCost ?? 0;

        // 取栈顶和 Top3
        const stackTop = log.stack?.[log.stack.length - 1] ?? '';
        const stackTop3 = log.stack?.slice(-3).reverse() ?? [];

        // 判断是否操作存储
        const isStorage = op === 'SSTORE' || op === 'SLOAD';

        // Storage slot mapping
        let storageSlotName = '';
        if (isStorage && log.stack?.length > 0) {
            const slotHex = log.stack[log.stack.length - (op === 'SSTORE' ? 2 : 1)];
            const slotNorm = normalizeSlot(slotHex);
            storageSlotName = STORAGE_NAMES[slotNorm] ?? slotNorm;
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
            stackTop,
            stackTop3,
            storageSlotName,
        });
    });

    // topOps 排序：先按 count 再按 gasCostSum
    const topOps = Object.entries(opCounts)
        .map(([op, count]) => {
            const gasCostSum = rows
                .filter(r => r.op === op)
                .reduce((acc, r) => acc + (r.gasCost ?? 0), 0);
            return { op, count, gasCostSum };
        })
        .sort((a, b) => {
            if (b.count !== a.count) return b.count - a.count;
            return b.gasCostSum - a.gasCostSum;
        })
        .slice(0, 10);

    // 输出 parsed_trace.json
    fs.writeFileSync(outFile, JSON.stringify({ rows, topOps }, null, 2), 'utf-8');

    console.log(`✓ parsed_trace.json generated with ${rows.length} rows`);
}

parseTrace();
