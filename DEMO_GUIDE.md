# Demo Recording Guide

For team members recording demo videos and live presentations of the EVM Trace Debugger & Vulnerability Detection tool.

## Quick Setup (5 minutes)

### 1. Pull Latest Branch

```bash
git clone https://github.com/Wwangjinghan/6107-BLOCKCHAIN-DEVELOPMENT-FUNDAMENTALS-PART2-.git
cd 6107-BLOCKCHAIN-DEVELOPMENT-FUNDAMENTALS-PART2-
git checkout demo-features
```

### 2. Generate Demo Data

```bash
# Generate trace analysis with synthetic call tree and gas suggestions
node scripts/parse_trace_local.cjs --demo

# Detect vulnerabilities and inject example finding
node scripts/vuln_detect.cjs --parsed parsed_trace.json --trace trace.json --out findings.json --demo
```

Or combine in one command:
```bash
node scripts/parse_trace_local.cjs --demo && node scripts/vuln_detect.cjs --parsed parsed_trace.json --trace trace.json --out findings.json --demo
```

### 3. Start Local Server

```bash
python -m http.server 8000
```

Or use Node's http-server:
```bash
npx http-server -p 8000
```

### 4. Open in Browser

- **Demo Page (with synthetic findings)**: http://localhost:8000/index.html?demo=1
- **Regular Page**: http://localhost:8000/index.html
- **Dashboard**: http://localhost:8000/dashboard.html

---

## What to Highlight in Demo

### Left Panel: Execution Trace
- **Scroll through steps** 1-123 to show full transaction execution
- **Click on steps** to highlight different opcodes
- Point out key operations:
  - Step 4: `CALLVALUE` (purple highlight)
  - Step 66: `CALLDATALOAD` (blue highlight)
  - Step 118: `SSTORE` (storage write - prominent)
  - Step 123: `STOP` (end of execution)

### Right Panel: Vulnerability Findings
- **Demo injection shows**: High-severity reentrancy vulnerability
- **Description**: "External call at step 65 followed by state modifications at step 117"
- **Recommendation**: "Implement checks-effects-interactions pattern and reentrancy guards"

### Bottom Panel: Call Tree & Gas Suggestions
Scroll down to show:
- **Call Tree**: Nested structure with CALL and DELEGATECALL operations
  - ID 0: CALL @ step 34
  - ID 1: CALL @ step 66 (nested)
  - ID 2: DELEGATECALL @ step 118
- **Gas Suggestions**:
  1. **Optimize SSTORE** (High) - 2,210 gas savings
  2. **Reduce Function Complexity** (Medium) - 850 gas savings
  3. **Optimize Loops** (Low) - 320 gas savings

### Top Right: Gas Operations Chart
- **Bar chart** showing frequency of top opcodes by gas usage
- **Click steps** to update chart with cumulative operations up to that point
- Highlight: SSTORE dominates the gas cost (22,100 gas)

---

## Recording Tips

### 1. **Smooth Flow**
- Start with full page view (show all panels)
- Slowly scroll through execution steps (steps 1→123)
- Pause on significant operations (especially SSTORE at step 118)

### 2. **Zoom & Highlight** (Optional)
- Use browser zoom (Ctrl/Cmd +) for larger text on screen recording
- Highlight text or use cursor pause for key findings

### 3. **Narration Points**
```
"This is a live transaction trace at the EVM opcode level.
 Each step represents an operation, with its program counter, opcode name, and gas cost.
 
 Looking at step 118, we see an SSTORE operation (storage write).
 This is one of the most expensive operations, costing 22,100 gas alone.
 
 On the right, we can see vulnerability detection results:
 This synthetic example flagged a potential reentrancy issue
 where an external call is followed by a state modification.
 
 Below that, we have optimization suggestions:
 - SSTORE optimization could save 2,210 gas
 - Function complexity reduction: 850 gas
 - Loop optimization: 320 gas
 
 The call tree shows the nested structure of contract interactions,
 helping us understand the execution flow and identify security issues."
```

### 4. **Screen Recording Setup**
- Use **OBS Studio** or **ScreenFlow** (Mac) / **ShareX** (Windows)
- Recommended resolution: 1920x1080 @ 30 FPS
- Browser window: Full screen or maximize
- Audio: Clear narration with background noise minimized

### 5. **Video Length**
- Optimal demo: 2-3 minutes
- Start: Basic overview (15 sec)
- Execution trace: Trace through steps (60 sec)
- Findings & optimization: Explain detections (45 sec)

---

## Live Presentation Mode

### Using `?demo=1` Parameter

Open http://localhost:8000/index.html?demo=1 to enable:
- Synthetic reentrancy vulnerability in UI
- Demo-specific injected finding (in addition to file-based findings.json)
- Useful for revealing "detected" issues in real-time without modifying the data files

### Without Demo Parameter

Open http://localhost:8000/index.html for:
- Real findings from `findings.json`
- Actual call tree and gas suggestions
- Production-like presentation

---

## Troubleshooting

### Server won't start
```bash
# Check if port 8000 is in use
# On Windows:
netstat -ano | findstr :8000
# Kill the process:
taskkill /PID <PID> /F

# Try different port:
python -m http.server 8001
```

### Data not updating
- Hard refresh browser: Ctrl+Shift+R (Windows) or Cmd+Shift+R (Mac)
- Clear browser cache
- Regenerate data:
  ```bash
  node scripts/parse_trace_local.cjs --demo
  node scripts/vuln_detect.cjs --parsed parsed_trace.json --trace trace.json --out findings.json --demo
  ```

### JavaScript errors in console
- Open DevTools: F12
- Check Console tab for errors
- Ensure `parsed_trace.json` and `findings.json` exist in project root
- Verify both files have valid JSON (use jsonlint.com to validate)

---

## File Manifest for Demo

Ensure these files are present and up-to-date:

- ✅ `index.html` - Main debugger UI with demo mode support
- ✅ `dashboard.html` - Global dashboard view
- ✅ `parsed_trace.json` - Generated with demo data (run `parse_trace_local.cjs --demo`)
- ✅ `findings.json` - Generated with demo vulnerability (run `vuln_detect.cjs --demo`)
- ✅ `trace.json` - Original trace file (read-only)
- ✅ `scripts/parse_trace_local.cjs` - Local parser with `--demo` flag
- ✅ `scripts/vuln_detect.cjs` - Detector with `--demo` flag

---

## Contact

For technical questions during recording:
- Check the main README.md for architecture details
- Review source code comments in `index.html` and `scripts/` for implementation details
- Refer to vulnerability rule documentation in `VULNERABILITY_DETECTION.md`

---

**Last Updated**: 2026-02-12  
**Branch**: `demo-features`  
**Status**: Ready for recording
