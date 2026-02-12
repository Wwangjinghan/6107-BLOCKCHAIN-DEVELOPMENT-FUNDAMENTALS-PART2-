#!/usr/bin/env node
/**
 * static_scan.js - Static Analysis Integration (Slither & Mythril)
 * 
 * Runs Slither and Mythril on ./contracts directory and normalizes output.
 * Findings are merged with dynamic trace analysis for a comprehensive report.
 * 
 * Requirements:
 *   - slither (pip install slither-analyzer)
 *   - mythril (pip install mythril)
 * 
 * Usage:
 *   node scripts/static_scan.js --contracts ./contracts --out static_findings.json
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// ====== Configuration ======
const SOLIDITY_SRC_DIR = './contracts';
const OUTPUT_DIR = '.';

// ====== CLI Argument Parser ======
function parseArgs() {
  const args = process.argv.slice(2);
  const result = { contracts: SOLIDITY_SRC_DIR, out: 'static_findings.json', skip_mythril: false };
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--contracts' && args[i + 1]) result.contracts = args[i + 1];
    if (args[i] === '--out' && args[i + 1]) result.out = args[i + 1];
    if (args[i] === '--skip-mythril') result.skip_mythril = true;
  }
  return result;
}

// ====== Tool Checkers ======
function hasSlither() {
  try {
    execSync('slither --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function hasMythril() {
  try {
    execSync('myth --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

// ====== Slither Integration ======
function runSlither(contractDir) {
  const findings = [];
  
  try {
    console.log(`Running Slither on ${contractDir}...`);
    const output = execSync(`slither ${contractDir} --json -`, { encoding: 'utf-8', stdio: 'pipe' });
    
    try {
      const slitherData = JSON.parse(output);
      
      if (slitherData.results) {
        let vulnId = 1;
        
        slitherData.results.forEach(issue => {
          // Map Slither severity to our severity scale
          let severity = 'low';
          if (issue.impact === 'High') severity = 'critical';
          else if (issue.impact === 'Medium') severity = 'high';
          else if (issue.impact === 'Low') severity = 'medium';
          else if (issue.impact === 'Informational') severity = 'low';

          // Map Slither check to our rules
          const ruleMap = {
            'reentrancy': 'reentrancy',
            'arbitrary-send': 'unchecked_call',
            'access-control': 'access_control',
            'integer-overflow': 'overflow',
            'low-level-calls': 'unchecked_call',
            'tx-origin': 'tx_origin',
            'delegatecall': 'delegatecall'
          };

          const rule = ruleMap[issue.check] || issue.check;

          findings.push({
            id: `SLITHER-${String(vulnId++).padStart(4, '0')}`,
            source: 'slither',
            rule,
            severity,
            title: `${issue.check}: ${issue.description?.substring(0, 60)}` || issue.check,
            description: issue.description || issue.check,
            evidence: {
              check: issue.check,
              impact: issue.impact,
              confidence: issue.confidence || 'unknown',
              elements: issue.elements?.length || 0
            },
            recommendation: `Review Slither findings: ${issue.check}`
          });
        });

        console.log(`  ✓ Found ${findings.length} issues`);
      }
    } catch (parseErr) {
      console.warn(`  ⚠ Could not parse Slither JSON: ${parseErr.message}`);
    }
  } catch (err) {
    if (err.code === 127) {
      console.warn(`  ⚠ Slither not found. Install: pip install slither-analyzer`);
    } else {
      console.warn(`  ⚠ Slither error: ${err.message.substring(0, 100)}`);
    }
  }

  return findings;
}

// ====== Mythril Integration ======
function runMythril(contractDir) {
  const findings = [];
  
  // Get .sol files
  const solFiles = getAllSolFiles(contractDir);
  if (solFiles.length === 0) {
    console.warn(`  ⚠ No .sol files found in ${contractDir}`);
    return findings;
  }

  console.log(`Running Mythril on ${solFiles.length} contract(s)...`);
  
  let vulnId = 1;
  
  solFiles.forEach(file => {
    try {
      // Mythril outputs JSON with --json flag
      const output = execSync(`myth analyze ${file} --json`, { encoding: 'utf-8', stdio: 'pipe' });
      
      try {
        const issues = JSON.parse(output);
        if (Array.isArray(issues)) {
          issues.forEach(issue => {
            // Map Mythril severity/type to ours
            let severity = 'low';
            if (issue.severity === 'High') severity = 'high';
            else if (issue.severity === 'Critical') severity = 'critical';
            else if (issue.severity === 'Medium') severity = 'medium';

            let rule = 'code_issue';
            if (issue.title.includes('Reentrancy')) rule = 'reentrancy';
            if (issue.title.includes('Integer')) rule = 'overflow';
            if (issue.title.includes('Unchecked')) rule = 'unchecked_call';
            if (issue.title.includes('Delegatecall')) rule = 'delegatecall';
            if (issue.title.includes('tx.origin')) rule = 'tx_origin';

            findings.push({
              id: `MYTHRIL-${String(vulnId++).padStart(4, '0')}`,
              source: 'mythril',
              rule,
              severity,
              title: issue.title,
              description: issue.description || issue.title,
              evidence: {
                type: issue.type,
                code: issue.code?.substring(0, 200) || '',
                pc: issue.pc || 0
              },
              recommendation: `Review Mythril finding: ${issue.title}`
            });
          });
        }
      } catch (parseErr) {
        console.warn(`  ⚠ Could not parse Mythril JSON for ${path.basename(file)}`);
      }
    } catch (err) {
      // Mythril may fail on some contracts, continue with others
      console.warn(`  ⚠ Mythril error on ${path.basename(file)}`);
    }
  });

  console.log(`  ✓ Mythril analysis complete`);
  return findings;
}

// ====== Utility Functions ======
function getAllSolFiles(dir) {
  const files = [];
  
  const walk = (dir) => {
    try {
      const items = fs.readdirSync(dir);
      items.forEach(item => {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          walk(fullPath);
        } else if (item.endsWith('.sol')) {
          files.push(fullPath);
        }
      });
    } catch (err) {
      // skip on error
    }
  };
  
  walk(dir);
  return files;
}

// ====== Merge & Deduplicate Findings ======
function mergeFindings(slitherFindings, mythrilFindings) {
  const all = [...slitherFindings, ...mythrilFindings];
  
  // Simple deduplication: group by rule and first occurrence
  const seen = {};
  const merged = [];
  
  all.forEach(finding => {
    const key = `${finding.rule}:${finding.severity}`;
    if (!seen[key]) {
      seen[key] = true;
      merged.push(finding);
    }
  });

  return merged.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
}

// ====== Main Entry Point ======
function main() {
  const args = parseArgs();

  if (!fs.existsSync(args.contracts)) {
    console.error(`❌ Contracts directory not found: ${args.contracts}`);
    process.exit(1);
  }

  console.log(`📊 Static Analysis Scan`);
  console.log(`  Contracts: ${args.contracts}`);
  console.log(`  Slither: ${hasSlither() ? '✓' : '✗'}`);
  console.log(`  Mythril: ${hasMythril() ? '✓' : '✗'}`);
  console.log('');

  const slitherFindings = hasSlither() ? runSlither(args.contracts) : [];
  const mythrilFindings = (!args.skip_mythril && hasMythril()) ? runMythril(args.contracts) : [];
  
  const merged = mergeFindings(slitherFindings, mythrilFindings);

  const output = {
    findings: merged,
    summary: {
      total: merged.length,
      critical: merged.filter(f => f.severity === 'critical').length,
      high: merged.filter(f => f.severity === 'high').length,
      medium: merged.filter(f => f.severity === 'medium').length,
      low: merged.filter(f => f.severity === 'low').length,
      sources: {
        slither: slitherFindings.length,
        mythril: mythrilFindings.length
      }
    }
  };

  fs.writeFileSync(args.out, JSON.stringify(output, null, 2));
  
  console.log('\n✓ Static analysis complete');
  console.log(`  Total: ${output.summary.total} issues (${output.summary.critical} critical, ${output.summary.high} high)`);
  console.log(`  Output: ${args.out}`);
}

if (require.main === module) {
  main();
}

module.exports = { runSlither, runMythril, mergeFindings };
