# Storage Diff Report - Demo.sol State Change Analysis

## Execution Result

**Storage Diff for Demo.sol (slot=0): Before=0 | After=42**

**Generated**: Automatically generated via state-diff.js

---

## Table of Contents

1. [Details](#details)
2. [Implementation Logic](#implementation-logic)
3. [Use Cases](#use-cases)
4. [Limitations](#limitations)
5. [Improvement Directions](#improvement-directions)
6. [Usage Guide](#usage-guide)

---

## Details

### Overview

This is a simplified Storage Diff analysis tool for **Demo.sol**, specifically designed to track changes in the contract's state variable `x` (located at storage slot=0).

- **Contract**: Demo.sol
- **Tracked Variable**: `x` (slot=0)
- **Data Source**: parsed_trace.json (EVM execution trace)
- **Analysis Method**: Extract SSTORE operation records

### Storage Change Example

| Property | Value |
|----------|-------|
| **Variable Name** | `x` |
| **Slot** | `0` |
| **Before (Decimal)** | `0` |
| **After (Hex)** | `0x000000000000000000000000000000000000000000000000000000000000002a` |
| **After (Decimal)** | `42` |
| **Operation Type** | SSTORE |

### SSTORE Operation Details

```
Step: 117
PC: 112
Gas: 22113
Gas Cost: 22100
Depth: 1
```

---

## Implementation Logic

### Workflow

```
parsed_trace.json
       ↓
   [Read File]
       ↓
   [Get sstores Array]
       ↓
   [Filter op="SSTORE"]
       ↓
   [Filter slot=0]
       ↓
   [Extract Last Write Value]
       ↓
   [Convert Hex to Decimal]
       ↓
   [Generate Report and Docs]
```

### Core Functions

#### 1. `hexToDecimal(hexString)`
Convert hexadecimal string to decimal:
- Remove `0x` prefix
- Use BigInt to handle large numbers
- Return decimal string

**Example**:
```javascript
hexToDecimal('0x2a') → '42'
hexToDecimal('0x0000...002a') → '42'
```

#### 2. `normalizeSlot(slot)`
Normalize storage slot to 64 hexadecimal characters (uint256 format):
- Remove `0x` prefix
- Left-pad with zeros to 64 characters
- Facilitate comparison with slot=0

**Example**:
```javascript
normalizeSlot('0x0') → '0000000000000000000000000000000000000000000000000000000000000000'
```

#### 3. `generateStateDiff()`
Main function, executes the complete workflow:
1. Verify file existence
2. Parse JSON data
3. Filter SSTORE operations
4. Filter records with slot=0
5. Extract the value from the last write
6. Create docs directory
7. Generate Markdown report

### Data Extraction Logic

In SSTORE operation:

```json
{
  "step": 117,
  "pc": 112,
  "op": "SSTORE",
  "stackTop": "0000000000000000000000000000000000000000000000000000000000000000",  // ← slot
  "stackTop3": [
    "000000000000000000000000000000000000000000000000000000000000002a",  // ← value (value to store)
    "000000000000000000000000000000000000000000000000000000000000002a",
    "0000000000000000000000000000000000000000000000000000000000000000"
  ]
}
```

- **stackTop**: Storage slot (retrieved from stack top)
- **stackTop3[0]**: Value to store (3rd value from stack top)

---

## Use Cases

### ✓ Fully Applicable Scenarios

#### 1. Demo.sol State Variable Tracking
```solidity
// Demo.sol
contract Demo {
    uint public x;  // slot=0
    
    function setX(uint _x) public {
        x = _x;     // This operation generates an SSTORE
    }
}
```

- Storage changes of simple single variables
- Teaching demonstrations
- Functionality verification

#### 2. Learning Storage Mechanisms
- Understanding storage operations in EVM
- Learning how SSTORE works
- Understanding slots and storage values

#### 3. Debugging and Verification
- Quickly view contract state after execution
- Verify state changes meet expectations
- Simplified analysis workflow

### ✓ Partially Applicable Scenarios

#### 4. Simple Contract Testing
- When only need to focus on single state variable
- Preliminary contract logic verification

---

## Limitations

### ⚠️ Critical Limitations

#### 1. Hardcoded slot=0
```javascript
// Current implementation
const slot0Records = sstoreRecords.filter(record => {
  const slot = normalizeSlot(record.stackTop);
  const zeroSlot = '000...000';  // Hardcoded as 0
  return slot === zeroSlot;
});
```

**Issues**:
- Only supports slot=0 in Demo.sol
- Does not support other contracts
- Cannot work with multi-variable contracts

#### 2. Missing ABI Information
- Cannot automatically identify variable names and types
- Cannot parse slot meaning
- Cannot handle packed storage

**Example - Unsupported Cases**:
```solidity
contract Complex {
    uint8 a;      // slot=0, offset=0
    uint8 b;      // slot=0, offset=1
    uint256 c;    // slot=1
    mapping(address => uint) balances;  // slot=2+
}
```

#### 3. Missing History Records
- Only shows final state
- Does not record intermediate state changes
- Cannot track multiple writes

**Example**:
```solidity
function increment() public {
    x = 10;  // SSTORE 1
    x = 20;  // SSTORE 2
    x = 42;  // SSTORE 3 ← Only captures the last one
}
```

#### 4. Incomplete Tracing
- Only uses `sstores` data (simplified version)
- Loses execution context in `structLogs`
- Cannot recreate complete execution flow

### ⚠️ Medium Limitations

#### 5. No Support for Complex Storage Structures

**Mapping**:
```solidity
mapping(address => uint) balances;
// Actual slot calculation: keccak256(abi.encodePacked(key, slot))
```

**Arrays**:
```solidity
uint[] values;
// slot: array length stored at declaration slot
// elements stored at: keccak256(slot) + index
```

**Structs**:
```solidity
struct User {
    uint id;      // slot offset
    address addr; // slot offset
}
```

#### 6. No ABI Verification
- Does not verify if slot usage conforms to Solidity specifications
- Cannot detect storage conflicts
- Does not support proxy contract storage analysis

#### 7. Missing Type Parsing
- Hex to decimal is only basic conversion
- Does not handle special types like bool, address
- Does not support two's complement for signed integers

**Example**:
```javascript
// Current: Simple hex → dec conversion
hexToDecimal('0xffffffff...') // Very large number

// Should: Parse according to type
// int256: should identify as negative number -1
// bool: should identify as true
```

---

## Improvement Directions

### 🔧 Short-term Improvements (High Priority)

#### 1. Support Arbitrary Slot Specification
```javascript
// Improved version
function generateStateDiff(targetSlot = 0) {
  const targetSlotNormalized = normalizeSlot(targetSlot.toString(16));
  const targetRecords = sstoreRecords.filter(record => 
    normalizeSlot(record.stackTop) === targetSlotNormalized
  );
  // ...
}

// Usage: node state-diff.js --slot 1
```

#### 2. Add ABI Support
```javascript
// Read ABI from artifacts or JSON
const abi = JSON.parse(fs.readFileSync('Demo.json', 'utf-8')).abi;
const storageLayout = parseStorageLayout(abi);

// {
//   x: { slot: 0, type: 'uint256', offset: 0 }
// }
```

#### 3. Complete Execution History
```javascript
// Record all SSTORE operations at slot=0
const allChanges = slot0Records.map(record => ({
  step: record.step,
  value: hexToDecimal(record.stackTop3[0]),
  gas: record.gasCost
}));

// Output time series
console.table(allChanges);
```

### 🎯 Mid-term Improvements (Medium Priority)

#### 4. Support Complex Storage Structures
```javascript
// Parse mapping slot
function calculateMappingSlot(key, mappingSlot) {
  const packed = ethers.solidityPacked(['bytes32', 'uint256'], [key, mappingSlot]);
  return ethers.keccak256(packed);
}

// Support arrays
function calculateArrayElementSlot(arraySlot, index) {
  const baseSlot = ethers.keccak256(arraySlot);
  return BigInt(baseSlot) + BigInt(index);
}
```

#### 5. Type-Aware Parsing
```javascript
// Parse values correctly according to type
function parseStorageValue(hexValue, type) {
  switch (type) {
    case 'bool':
      return hexValue !== '0x00';
    case 'address':
      return '0x' + hexValue.slice(-40);
    case 'int256':
      return interpretAsSigned(hexValue);
    default:
      return hexToDecimal(hexValue);
  }
}
```

#### 6. Cross-Contract Support
```javascript
// Analyze multiple contracts
const contracts = ['Demo.sol', 'Token.sol', 'Vault.sol'];
for (const contract of contracts) {
  const trace = loadTrace(contract);
  const diff = generateStateDiff(trace);
  console.log(diff);
}
```

### 🚀 Long-term Improvements (Low Priority)

#### 7. Interactive Analysis Tool
- Web UI for visualizing storage changes
- Timeline showing state evolution
- Comparing impacts of different transactions

#### 8. Automated Verification
- Compare against contract source code
- Detect storage conflicts
- Verify optimized contracts (optimized layout)

#### 9. Multi-Trace Support
- Compare storage diffs across multiple transactions
- Detect storage race conditions
- Analyze state dependencies

---

## Usage Guide

### Prerequisites

1. **Node.js** is installed
2. **parsed_trace.json** exists in project root
3. **state-diff.js** script file exists

### Run Script

```bash
cd /path/to/project
node state-diff.js
```

### Output Example

**Console Output**:
```
✓ Found 1 SSTORE record
✓ Found 1 SSTORE record with slot=0
✓ Storage Diff for Demo.sol (slot=0): Before=0 | After=42
✓ Created directory: docs
✓ Results saved to: docs/state-diff.md
```

**Generated Files**:
- `docs/state-diff.md` - This Markdown report

### Error Handling

The script automatically captures the following errors:

| Error | Reason | Solution |
|-------|--------|----------|
| `File not found` | parsed_trace.json missing | Ensure file in project root |
| `sstores attribute not found` | JSON structure error | Check parsed_trace.json format |
| `No SSTORE operations found` | Contract did not modify state | Run transaction with state changes |
| `No slot=0 records found` | Modified different slot only | Verify contract modified x |

### Example Workflow

```bash
# 1. Run contract transaction (generate trace)
npm run deploy

# 2. Parse execution trace
node scripts/parse_trace.js

# 3. Generate storage diff report
node state-diff.js

# 4. View report
cat docs/state-diff.md
```

---

## Technical Details

### SSTORE Operation Principle

EVM instruction SSTORE workflow:

```
Stack Layout (from top to bottom):
┌──────────────────────────┐
│ ... other data           │
├──────────────────────────┤
│ value (value to store)   │ ← stackTop3[0]
│ (unused)                 │ ← stackTop3[1]
│ (unused)                 │ ← stackTop3[2]
│ slot (storage location)  │ ← stackTop
├──────────────────────────┤
│ ... more stack data      │
└──────────────────────────┘

Execute SSTORE:
  memory[slot] = value
  gas cost = 22100 (new write) or 2900 (update)
```

### Slot Calculation Rules

**State Variables in Order**:

```solidity
contract Demo {
    uint256 x;       // slot 0
    uint128 y;       // slot 1
    uint128 z;       // slot 1 (shares with y)
    address owner;   // slot 2
    mapping(addr => uint) map;  // slot 3
}

Storage Layout:
┌───────────────────────────┬────────┐
│ x (32 bytes)              │ slot 0 │
├───────────────────────────┼────────┤
│ z (16 bytes) │ y (16 bytes)│ slot 1 │
├───────────────────────────┼────────┤
│ owner (20 bytes) + padding│ slot 2 │
├───────────────────────────┼────────┤
│ mapping base             │ slot 3 │
└───────────────────────────┴────────┘
```

---

## References

- [Solidity Documentation - Storage Layout](https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html)
- [Ethereum Yellow Paper - SSTORE Instruction](https://ethereum.org/en/developers/docs/evm/opcodes/)
- [Hardhat Documentation - Debugging](https://hardhat.org/hardhat-network/docs/reference)

---

## Summary

This Storage Diff tool is a simplified implementation for **Demo.sol**, focusing on clear presentation of single-variable analysis. Although functionally limited, it effectively demonstrates the basic principles of EVM storage operations. For more complex analysis needs, a combination of multiple improvement directions would be required.

