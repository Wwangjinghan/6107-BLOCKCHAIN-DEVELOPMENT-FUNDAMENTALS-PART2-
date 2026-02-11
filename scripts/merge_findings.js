/**
 * merge_findings.js - Merge and deduplicate findings from dynamic and static analysis
 * 
 * Normalizes findings from Slither/Mythril into standard schema and merges with dynamic findings.
 * De-duplicates based on rule category and contract/function.
 * Preserves higher severity and merges evidence arrays.
 * 
 * Exported function:
 *   mergeFindings(dynamicFindings, slitherFindings, mythrilFindings) -> mergedFindings
 */

const fs = require('fs');

/**
 * Normalize Slither findings into standard findings schema
 * @param {Array|Object} slitherData - Parsed slither.json result
 * @returns {Array} Array of normalized findings
 */
function normalizeSlitherFindings(slitherData) {
  const findings = [];
  if (!slitherData) return findings;

  // Slither output can be { results: [...] } or direct results array
  const results = slitherData.results || (Array.isArray(slitherData) ? slitherData : []);

  if (!Array.isArray(results)) return findings;

  results.forEach((result, idx) => {
    if (!result || !result.check) return;

    const ruleMap = mapSlitherCheckToRule(result.check);
    const severity = mapSlitherSeverity(result.impact);

    const finding = {
      id: `STATIC-SLITHER-${String(idx + 1).padStart(4, '0')}`,
      rule: ruleMap,
      severity,
      title: result.check,
      description: result.description || `Slither detected: ${result.check}`,
      evidence: {
        source: 'Slither',
        check: result.check,
        impact: result.impact,
        elements: result.elements || []
      },
      recommendation: getSlitherRecommendation(result.check),
      tags: ['static', 'slither', ruleMap]
    };

    findings.push(finding);
  });

  return findings;
}

/**
 * Normalize Mythril findings into standard findings schema
 * @param {Array|Object} mythrilData - Parsed mythril.json result
 * @returns {Array} Array of normalized findings
 */
function normalizeMythrilFindings(mythrilData) {
  const findings = [];
  if (!mythrilData) return findings;

  // Mythril output can be { issues: [...] } or direct issues array
  const issues = mythrilData.issues || (Array.isArray(mythrilData) ? mythrilData : []);

  if (!Array.isArray(issues)) return findings;

  issues.forEach((issue, idx) => {
    if (!issue || !issue.title) return;

    const ruleMap = mapMythrilTitleToRule(issue.title);
    const severity = mapMythrilSeverity(issue.severity);

    const finding = {
      id: `STATIC-MYTHRIL-${String(idx + 1).padStart(4, '0')}`,
      rule: ruleMap,
      severity,
      title: issue.title,
      description: issue.description || `Mythril detected: ${issue.title}`,
      evidence: {
        source: 'Mythril',
        title: issue.title,
        severity: issue.severity,
        type: issue.type || 'Informational'
      },
      recommendation: getMythrilRecommendation(issue.title),
      tags: ['static', 'mythril', ruleMap]
    };

    findings.push(finding);
  });

  return findings;
}

/**
 * Map Slither check names to standard rule categories
 * @param {string} check - Slither check name
 * @returns {string} Normalized rule name
 */
function mapSlitherCheckToRule(check) {
  const checkLower = check.toLowerCase();

  if (checkLower.includes('reentrancy') || checkLower.includes('reentrancy-benign') || checkLower.includes('reentrancy-events')) {
    return 'ReentrancyHeuristicFrame';
  }
  if (checkLower.includes('arithmetic') || checkLower.includes('overflow') || checkLower.includes('underflow')) {
    return 'ArithmeticOverflowUnderflow';
  }
  if (checkLower.includes('delegatecall')) {
    return 'DelegatecallTargetHeuristic';
  }
  if (checkLower.includes('tx-origin') || checkLower.includes('tx.origin')) {
    return 'TxOriginAuthHeuristic';
  }
  if (checkLower.includes('unchecked-call') || checkLower.includes('unchecked-send')) {
    return 'UncheckedExternalCall';
  }
  if (checkLower.includes('access-control') || checkLower.includes('permission')) {
    return 'AccessControlIssue';
  }

  // Default: use check name as rule
  return check;
}

/**
 * Map Mythril issue titles to standard rule categories
 * @param {string} title - Mythril issue title
 * @returns {string} Normalized rule name
 */
function mapMythrilTitleToRule(title) {
  const titleLower = title.toLowerCase();

  if (titleLower.includes('reentrancy')) {
    return 'ReentrancyHeuristicFrame';
  }
  if (titleLower.includes('arithmetic') || titleLower.includes('overflow') || titleLower.includes('underflow')) {
    return 'ArithmeticOverflowUnderflow';
  }
  if (titleLower.includes('delegatecall')) {
    return 'DelegatecallTargetHeuristic';
  }
  if (titleLower.includes('tx-origin') || titleLower.includes('tx.origin') || titleLower.includes('tx_origin')) {
    return 'TxOriginAuthHeuristic';
  }
  if (titleLower.includes('call') || titleLower.includes('return')) {
    return 'UncheckedExternalCall';
  }
  if (titleLower.includes('access') || titleLower.includes('permission')) {
    return 'AccessControlIssue';
  }

  // Default: use title as rule
  return title;
}

/**
 * Map Slither impact to severity
 */
function mapSlitherSeverity(impact) {
  const severityMap = {
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
    'informational': 'low',
    'optimization': 'low'
  };
  return severityMap[(impact || '').toLowerCase()] || 'medium';
}

/**
 * Map Mythril severity to standard severity
 */
function mapMythrilSeverity(severity) {
  const severityMap = {
    'High': 'high',
    'Medium': 'medium',
    'Low': 'low',
    'Informational': 'low'
  };
  return severityMap[severity] || 'medium';
}

/**
 * Get recommendation for Slither check
 */
function getSlitherRecommendation(check) {
  const checkLower = check.toLowerCase();

  if (checkLower.includes('reentrancy')) {
    return 'Use checks-effects-interactions pattern. Consider reentrancy guards (OpenZeppelin).';
  }
  if (checkLower.includes('arithmetic')) {
    return 'Upgrade to Solidity >=0.8 for built-in overflow checks. Use SafeMath for earlier versions.';
  }
  if (checkLower.includes('delegatecall')) {
    return 'Ensure delegatecall target is whitelisted and audited. Avoid dynamic targets.';
  }
  if (checkLower.includes('tx-origin')) {
    return 'Never use tx.origin for access control. Use msg.sender instead.';
  }

  return 'Review and apply appropriate mitigation measures.';
}

/**
 * Get recommendation for Mythril issue
 */
function getMythrilRecommendation(title) {
  const titleLower = title.toLowerCase();

  if (titleLower.includes('reentrancy')) {
    return 'Use checks-effects-interactions pattern. Consider reentrancy guards (OpenZeppelin).';
  }
  if (titleLower.includes('arithmetic')) {
    return 'Upgrade to Solidity >=0.8 for built-in overflow checks. Use SafeMath for earlier versions.';
  }
  if (titleLower.includes('delegatecall')) {
    return 'Ensure delegatecall target is whitelisted and audited. Avoid dynamic targets.';
  }
  if (titleLower.includes('tx-origin')) {
    return 'Never use tx.origin for access control. Use msg.sender instead.';
  }

  return 'Review and apply appropriate mitigation measures.';
}

/**
 * Extract contract/function context from a finding
 * Best-effort extraction from evidence or description
 * @param {Object} finding - Finding object
 * @returns {string} Context string for comparison
 */
function extractFindingContext(finding) {
  let context = '';

  // Try evidence first
  if (finding.evidence) {
    if (finding.evidence.frameId !== undefined) {
      context += `frame:${finding.evidence.frameId}`;
    }
    if (finding.evidence.contract) {
      context += `contract:${finding.evidence.contract}`;
    }
    if (finding.evidence.function) {
      context += `function:${finding.evidence.function}`;
    }
  }

  // Try rule name as fallback
  if (!context && finding.rule) {
    context = finding.rule;
  }

  return context;
}

/**
 * Severity ranking (higher number = higher priority)
 */
function severityRank(severity) {
  const ranks = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };
  return ranks[severity] || 0;
}

/**
 * Main: Merge findings from dynamic and static analysis
 * @param {Array} dynamicFindings - Findings from dynamic trace analysis
 * @param {Array|Object} slitherData - Raw or parsed Slither output
 * @param {Array|Object} mythrilData - Raw or parsed Mythril output
 * @returns {Array} Merged and deduplicated findings
 */
function mergeFindings(dynamicFindings, slitherData, mythrilData) {
  const allFindings = [];
  const findingMap = new Map(); // Map by context to track duplicates

  // Normalize static findings
  const slitherFindings = normalizeSlitherFindings(slitherData);
  const mythrilFindings = normalizeMythrilFindings(mythrilData);

  // Add all dynamic findings first
  if (Array.isArray(dynamicFindings)) {
    dynamicFindings.forEach((finding) => {
      const context = extractFindingContext(finding);
      const key = `${finding.rule}:${context}`;

      if (!findingMap.has(key)) {
        findingMap.set(key, finding);
        allFindings.push(finding);
      }
    });
  }

  // Merge static findings
  const staticFindings = [...slitherFindings, ...mythrilFindings];

  staticFindings.forEach((staticFinding) => {
    const context = extractFindingContext(staticFinding);
    const key = `${staticFinding.rule}:${context}`;

    const existing = findingMap.get(key);

    if (existing) {
      // Merge with existing finding: keep higher severity, merge evidence
      if (severityRank(staticFinding.severity) > severityRank(existing.severity)) {
        existing.severity = staticFinding.severity;
      }

      // Merge evidence arrays
      if (!existing.evidence) {
        existing.evidence = [];
      }
      if (!Array.isArray(existing.evidence)) {
        existing.evidence = [existing.evidence];
      }

      if (staticFinding.evidence) {
        if (Array.isArray(staticFinding.evidence)) {
          existing.evidence.push(...staticFinding.evidence);
        } else {
          existing.evidence.push(staticFinding.evidence);
        }
      }

      // Merge tags
      if (staticFinding.tags) {
        const tagsSet = new Set(existing.tags || []);
        staticFinding.tags.forEach((tag) => tagsSet.add(tag));
        existing.tags = Array.from(tagsSet);
      }

      // Update title/description to indicate merged
      if (!existing.title.includes('[MERGED]')) {
        existing.title = `[MERGED] ${existing.title}`;
      }
    } else {
      // New finding
      findingMap.set(key, staticFinding);
      allFindings.push(staticFinding);
    }
  });

  return allFindings;
}

module.exports = {
  mergeFindings,
  normalizeSlitherFindings,
  normalizeMythrilFindings,
  mapSlitherCheckToRule,
  mapMythrilTitleToRule
};
