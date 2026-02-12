/**
 * EVM Call Frame Reconstruction from structLogs
 * 
 * Reconstructs call frames (CALL, DELEGATECALL, STATICCALL, CALLCODE, CREATE, CREATE2)
 * from Hardhat debug_traceTransaction structLogs, maintaining parent-child relationships
 * and extracting call parameters from EVM stack and memory.
 */

/**
 * Helper: Read memory bytes from structLogs memory array
 * @param {Array} memoryWords - Memory array from structLogs[i].memory (array of 32-byte hex strings)
 * @param {number} offset - Byte offset to start reading
 * @param {number} size - Number of bytes to read
 * @returns {string} Hex string (0x...)
 */
function readMemory(memoryWords, offset, size) {
  if (!memoryWords || !size || size === 0) return "0x";

  let result = "";
  const memoryBytes = [];

  // Flatten memory words to individual bytes
  for (const word of memoryWords) {
    const hexStr = word.replace("0x", "").padStart(64, "0");
    for (let j = 0; j < 32; j++) {
      memoryBytes.push(hexStr.substring(j * 2, j * 2 + 2));
    }
  }

  // Extract bytes from offset to offset+size
  for (let i = offset; i < offset + size && i < memoryBytes.length; i++) {
    result += memoryBytes[i];
  }

  // Pad with zeros if we didn't have enough memory
  while (result.length < size * 2) {
    result += "00";
  }

  return "0x" + result;
}

/**
 * Helper: Get function selector (first 4 bytes of calldata)
 * @param {string} calldata - Hex string calldata (0x...)
 * @returns {string|null} Selector or null
 */
function getSelector(calldata) {
  if (!calldata || calldata.length < 10) return null;
  return calldata.substring(0, 10);
}

/**
 * Helper: Convert hex string to number
 * @param {string} hex - Hex string (0x...)
 * @returns {number}
 */
function hexToNumber(hex) {
  if (!hex || hex === "0x") return 0;
  try {
    return parseInt(hex, 16);
  } catch {
    return 0;
  }
}

/**
 * Helper: Convert number to hex string
 * @param {number|string} num
 * @returns {string} Hex string (0x...)
 */
function numberToHex(num) {
  if (typeof num === "string") {
    if (num.startsWith("0x")) return num;
    return "0x" + parseInt(num, 10).toString(16);
  }
  return "0x" + num.toString(16);
}

/**
 * Helper: Extract address from hex string (right-padded, use last 40 chars)
 * @param {string} hex - Hex string
 * @returns {string} Address (0x + 40 chars)
 */
function extractAddress(hex) {
  if (!hex) return "0x" + "0".repeat(40);
  const clean = hex.replace("0x", "").toLowerCase();
  const addr = clean.length >= 40 ? clean.slice(-40) : clean.padStart(40, "0");
  return "0x" + addr;
}

/**
 * Main: Reconstruct call frames from structLogs
 * @param {Array} structLogs - Debug trace structLogs from debug_traceTransaction
 * @param {Object} txMeta - Transaction metadata {from, to, input, value, ...}
 * @returns {Object} {frames: Array, stepToFrameId: Array}
 */
function buildCallFrames(structLogs, txMeta) {
  if (!structLogs || structLogs.length === 0) {
    return { frames: [], stepToFrameId: [] };
  }

  const frames = [];
  const frameStack = [];
  const stepToFrameId = [];
  let nextFrameId = 0;

  // Create root frame
  const rootFrame = {
    id: nextFrameId++,
    parentId: null,
    depthEnter: 0,
    depth: 0,
    type: "ROOT",
    from: txMeta.from ? txMeta.from.toLowerCase() : null,
    to: txMeta.to ? txMeta.to.toLowerCase() : null,
    value: txMeta.value ? numberToHex(txMeta.value) : "0x0",
    input: txMeta.input || null,
    selector: txMeta.input ? getSelector(txMeta.input) : null,
    gasSpent: 0,
    startStep: 0,
    endStep: structLogs.length > 0 ? structLogs.length - 1 : 0,
    success: null,
    error: null,
    children: []
  };

  frames.push(rootFrame);
  frameStack.push(rootFrame);

  let lastDepth = 0;

  // Process each step
  for (let step = 0; step < structLogs.length; step++) {
    const log = structLogs[step];
    const opcode = log.op || "UNKNOWN";
    const depth = log.depth || 0;
    const stack = log.stack || [];
    const memory = log.memory || [];

    // Get current active frame
    const currentFrame = frameStack[frameStack.length - 1];
    if (!currentFrame) {
      stepToFrameId.push(frames[0].id);
      continue;
    }

    // Record current frame for this step
    stepToFrameId.push(currentFrame.id);

    // Add gas cost to current frame
    const gasCost = hexToNumber(log.gasCost);
    if (gasCost > 0) {
      currentFrame.gasSpent += gasCost;
    }

    // Handle frame exit: depth decreased
    if (depth < lastDepth) {
      // Pop frames that are deeper than current depth
      while (frameStack.length > 1 && frameStack[frameStack.length - 1].depth >= depth) {
        const exitingFrame = frameStack.pop();
        exitingFrame.endStep = step - 1;

        // Infer success/error from context
        // If next step is REVERT, this frame failed
        if (step < structLogs.length) {
          const nextLog = structLogs[step];
          if (nextLog.op === "REVERT") {
            exitingFrame.error = "REVERT";
            exitingFrame.success = false;
          } else if (nextLog.op === "INVALID") {
            exitingFrame.error = "INVALID";
            exitingFrame.success = false;
          } else if (exitingFrame.type !== "ROOT" && exitingFrame.success === null) {
            exitingFrame.success = true;
          }
        }
      }
    }

    // Handle frame entry: CALL/CREATE opcodes
    if (
      opcode === "CALL" ||
      opcode === "DELEGATECALL" ||
      opcode === "STATICCALL" ||
      opcode === "CALLCODE" ||
      opcode === "CREATE" ||
      opcode === "CREATE2"
    ) {
      const newFrame = {
        id: nextFrameId++,
        parentId: currentFrame.id,
        depthEnter: depth,
        depth: depth + 1,
        type: opcode,
        from: currentFrame.to,
        to: null,
        value: null,
        input: null,
        selector: null,
        gasSpent: 0,
        startStep: step,
        endStep: step,
        success: null,
        error: null,
        children: []
      };

      // Parse call parameters from stack
      // Stack indexing: [0] = top (last pushed), [n-1] = bottom (first item)
      // Order of parameters in EVM: gas, addr/to, [value], inOffset, inSize, [outOffset], [outSize]
      // On stack when opcode is about to execute:
      // stack[0] = last parameter, ..., stack[n] = first parameter

      if (opcode === "CALL") {
        // CALL gas, to, value, inOffset, inSize, outOffset, outSize
        // Stack: [outSize(0), outOffset(1), inSize(2), inOffset(3), value(4), to(5), gas(6), ...]
        if (stack.length >= 7) {
          newFrame.to = extractAddress(stack[5]); // index 5 from top
          newFrame.value = stack[4]; // index 4 from top
          const inOffset = hexToNumber(stack[3]);
          const inSize = hexToNumber(stack[2]);
          newFrame.input = readMemory(memory, inOffset, inSize);
          newFrame.selector = getSelector(newFrame.input);
        }
      } else if (opcode === "DELEGATECALL") {
        // DELEGATECALL gas, to, inOffset, inSize, outOffset, outSize
        // Stack: [outSize(0), outOffset(1), inSize(2), inOffset(3), to(4), gas(5), ...]
        if (stack.length >= 6) {
          newFrame.to = extractAddress(stack[4]); // index 4 from top
          newFrame.value = "0x0";
          const inOffset = hexToNumber(stack[3]);
          const inSize = hexToNumber(stack[2]);
          newFrame.input = readMemory(memory, inOffset, inSize);
          newFrame.selector = getSelector(newFrame.input);
        }
      } else if (opcode === "STATICCALL") {
        // STATICCALL gas, to, inOffset, inSize, outOffset, outSize
        // Stack: [outSize(0), outOffset(1), inSize(2), inOffset(3), to(4), gas(5), ...]
        if (stack.length >= 6) {
          newFrame.to = extractAddress(stack[4]); // index 4 from top
          newFrame.value = "0x0";
          const inOffset = hexToNumber(stack[3]);
          const inSize = hexToNumber(stack[2]);
          newFrame.input = readMemory(memory, inOffset, inSize);
          newFrame.selector = getSelector(newFrame.input);
        }
      } else if (opcode === "CALLCODE") {
        // CALLCODE gas, to, value, inOffset, inSize, outOffset, outSize
        // Stack: [outSize(0), outOffset(1), inSize(2), inOffset(3), value(4), to(5), gas(6), ...]
        if (stack.length >= 7) {
          newFrame.to = extractAddress(stack[5]); // index 5 from top
          newFrame.value = stack[4];
          const inOffset = hexToNumber(stack[3]);
          const inSize = hexToNumber(stack[2]);
          newFrame.input = readMemory(memory, inOffset, inSize);
          newFrame.selector = getSelector(newFrame.input);
        }
      } else if (opcode === "CREATE") {
        // CREATE value, offset, size
        // Stack: [size(0), offset(1), value(2), ...]
        if (stack.length >= 3) {
          newFrame.value = stack[2];
          const offset = hexToNumber(stack[1]);
          const size = hexToNumber(stack[0]);
          newFrame.input = readMemory(memory, offset, size);
        }
      } else if (opcode === "CREATE2") {
        // CREATE2 value, offset, size, salt
        // Stack: [salt(0), size(1), offset(2), value(3), ...]
        if (stack.length >= 4) {
          newFrame.value = stack[3];
          const offset = hexToNumber(stack[2]);
          const size = hexToNumber(stack[1]);
          newFrame.input = readMemory(memory, offset, size);
        }
      }

      frames.push(newFrame);
      currentFrame.children.push(newFrame.id);
      frameStack.push(newFrame);
    }

    // Handle explicit frame exit opcodes (closing frames that made calls)
    if (opcode === "RETURN" || opcode === "REVERT" || opcode === "STOP" || opcode === "INVALID") {
      // These opcodes may exit one or more frames
      if (opcode === "REVERT" || opcode === "INVALID") {
        // Mark current frame as failed
        currentFrame.error = opcode;
        currentFrame.success = false;
      } else if (opcode === "RETURN" || opcode === "STOP") {
        if (currentFrame.type !== "ROOT" && currentFrame.success === null) {
          currentFrame.success = true;
        }
      }
    }

    lastDepth = depth;
  }

  // Close any remaining open frames
  while (frameStack.length > 1) {
    const exitingFrame = frameStack.pop();
    exitingFrame.endStep = structLogs.length - 1;
    if (exitingFrame.success === null) {
      exitingFrame.success = true; // Assume success if no error marker
    }
  }

  // Set root frame bounds and status
  if (structLogs.length > 0) {
    rootFrame.endStep = structLogs.length - 1;
    const lastLog = structLogs[structLogs.length - 1];
    if (lastLog.op === "REVERT") {
      rootFrame.error = "REVERT";
      rootFrame.success = false;
    } else if (lastLog.op === "INVALID") {
      rootFrame.error = "INVALID";
      rootFrame.success = false;
    } else {
      rootFrame.success = true;
    }
  } else {
    rootFrame.success = true;
  }

  return { frames, stepToFrameId };
}

/**
 * Validation: Check integrity of frame structure
 * @param {Array} frames - Array of frames
 * @returns {Object} {valid: boolean, issues: string[]}
 */
function validateFrames(frames) {
  const issues = [];
  const idSet = new Set(frames.map((f) => f.id));

  for (const frame of frames) {
    // Check parent exists
    if (frame.parentId !== null && !idSet.has(frame.parentId)) {
      issues.push(`Frame ${frame.id}: invalid parentId ${frame.parentId}`);
    }

    // Check children exist
    for (const childId of frame.children) {
      if (!idSet.has(childId)) {
        issues.push(`Frame ${frame.id}: invalid child ${childId}`);
      }
    }

    // Check depth consistency
    if (frame.parentId !== null) {
      const parent = frames.find((f) => f.id === frame.parentId);
      if (parent && frame.depth !== parent.depth + 1) {
        issues.push(
          `Frame ${frame.id}: depth ${frame.depth} != parent depth ${parent.depth} + 1`
        );
      }
    }

    // Check step ordering
    if (frame.endStep < frame.startStep) {
      issues.push(`Frame ${frame.id}: endStep < startStep`);
    }
  }

  return { valid: issues.length === 0, issues };
}

/**
 * Demo: Validate a sample trace structure
 * Tests buildCallFrames with a minimal structLogs array
 */
function demoValidation() {
  // Minimal sample structLogs with a CALL
  const sampleLogs = [
    {
      pc: 0,
      op: "PUSH1",
      gas: 10000,
      gasCost: 3,
      depth: 1,
      stack: ["0x60"],
      memory: []
    },
    {
      pc: 2,
      op: "CALL",
      gas: 9997,
      gasCost: 100,
      depth: 1,
      stack: [
        "0x00",
        "0x000000000000000000000000",
        "0x0000000000000000000000001234567890123456789012345678901234567890",
        "0x00",
        "0x00",
        "0x00",
        "0x00",
        "0x00"
      ],
      memory: []
    },
    {
      pc: 3,
      op: "RETURN",
      gas: 9897,
      gasCost: 0,
      depth: 1,
      stack: [],
      memory: []
    }
  ];

  const txMeta = {
    from: "0x1111111111111111111111111111111111111111",
    to: "0x2222222222222222222222222222222222222222",
    input: "0x12345678",
    value: "0x0"
  };

  const result = buildCallFrames(sampleLogs, txMeta);
  const validation = validateFrames(result.frames);

  console.log("=== Call Frames Demo ===");
  console.log(
    `Frames created: ${result.frames.length}, stepToFrameId length: ${result.stepToFrameId.length}`
  );
  console.log(`Validation: ${validation.valid ? "✓ PASS" : "✗ FAIL"}`);
  if (!validation.valid) {
    console.log("Issues:");
    validation.issues.forEach((issue) => console.log(`  - ${issue}`));
  }

  // Sample output
  if (result.frames.length > 0) {
    console.log("\nRoot frame:");
    console.log(`  id=${result.frames[0].id}, type=${result.frames[0].type}`);
    console.log(`  children=${result.frames[0].children.length}`);
  }

  return validation.valid;
}

module.exports = { buildCallFrames, validateFrames, demoValidation };
