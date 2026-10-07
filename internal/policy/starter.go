package policy

// Starter is the policy that "vet policy init" and "vet ci init --policy"
// write. It fails on the controls that need no tuning. It has no cooldown
// rule: the dependency-cooldown control reports a fresh version, and a
// rule on its severity decides the gate.
const Starter = `# vet policy v2. vet scan --policy FILE applies it.
# vet policy schema get prints the fields that a rule reads.
version: 2

rules:
  - id: no-malware
    description: A malicious or suspicious package fails the gate.
    when: finding.family == "malware"
    action: fail
  - id: no-critical-vulnerability
    when: finding.control_id == "vulnerability" && finding.severity == "critical"
    action: fail
  - id: workflow-risk
    when: finding.control_id in ["dangerous-trigger", "template-injection"]
    action: fail

# A suppression hides findings from the gate. The findings stay in the
# report. Set id, purl or control, a reason, and an optional expiry.
suppressions: []
#  - purl: pkg:npm/left-pad@1.3.0
#    control: dependency-cooldown
#    reason: Reviewed. The maintainer published a fix.
#    expires: 2026-12-31
`
