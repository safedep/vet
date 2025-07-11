# SQLite3 Reporter Query Examples

The SQLite3 reporter generates a comprehensive database with package manifest and dependency data that can be queried using standard SQL. Here are some useful example queries:

## Basic Queries

### List all package manifests
```sql
SELECT manifest_id, ecosystem, display_path, created_at 
FROM report_package_manifests 
ORDER BY created_at;
```

### List all packages with their basic information
```sql
SELECT name, version, ecosystem, is_direct, is_malware, is_suspicious 
FROM report_packages 
ORDER BY name;
```

### Find all direct dependencies
```sql
SELECT p.name, p.version, p.ecosystem, m.display_path
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
WHERE p.is_direct = 1
ORDER BY p.name;
```

## Security Analysis Queries

### Find all vulnerabilities
```sql
SELECT p.name, p.version, v.vulnerability_id, v.title, v.severity, v.cvss_score
FROM report_packages p
JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
ORDER BY v.severity DESC, v.cvss_score DESC;
```

### Find critical and high severity vulnerabilities
```sql
SELECT p.name, p.version, v.vulnerability_id, v.title, v.severity, m.display_path
FROM report_packages p
JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
WHERE v.severity IN ('CRITICAL', 'HIGH')
ORDER BY v.severity DESC;
```

### Count vulnerabilities by severity
```sql
SELECT v.severity, COUNT(*) as vulnerability_count
FROM report_vulnerabilities v
GROUP BY v.severity
ORDER BY vulnerability_count DESC;
```

### Find packages with most vulnerabilities
```sql
SELECT p.name, p.version, p.ecosystem, COUNT(v.id) as vuln_count
FROM report_packages p
LEFT JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
GROUP BY p.id, p.name, p.version, p.ecosystem
HAVING vuln_count > 0
ORDER BY vuln_count DESC;
```

### Find vulnerability aliases
```sql
SELECT p.name, p.version, v.vulnerability_id, v.aliases
FROM report_packages p
JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
WHERE v.aliases IS NOT NULL AND v.aliases != '[]';
```

## License Analysis Queries

### Find all licenses
```sql
SELECT p.name, p.version, l.license_id, l.name
FROM report_packages p
JOIN report_licenses l ON p.id = l.report_package_licenses
ORDER BY l.license_id, p.name;
```

### Count packages by license
```sql
SELECT l.license_id, COUNT(DISTINCT p.id) as package_count
FROM report_licenses l
JOIN report_packages p ON l.report_package_licenses = p.id
GROUP BY l.license_id
ORDER BY package_count DESC;
```

### Find packages with specific licenses
```sql
SELECT p.name, p.version, p.ecosystem, m.display_path
FROM report_packages p
JOIN report_licenses l ON p.id = l.report_package_licenses
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
WHERE l.license_id IN ('MIT', 'Apache-2.0', 'GPL-3.0')
ORDER BY l.license_id, p.name;
```

### License compliance overview by manifest
```sql
SELECT 
    m.display_path,
    COUNT(DISTINCT p.id) as total_packages,
    COUNT(DISTINCT l.license_id) as unique_licenses,
    GROUP_CONCAT(DISTINCT l.license_id) as all_licenses
FROM report_package_manifests m
LEFT JOIN report_package_manifest_packages mp ON m.id = mp.report_package_manifest_id
LEFT JOIN report_packages p ON mp.report_package_id = p.id
LEFT JOIN report_licenses l ON p.id = l.report_package_licenses
GROUP BY m.id, m.display_path
ORDER BY unique_licenses DESC;
```

### Find packages without license information
```sql
SELECT p.name, p.version, p.ecosystem, m.display_path
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
LEFT JOIN report_licenses l ON p.id = l.report_package_licenses
WHERE l.id IS NULL;
```

### Find potentially problematic licenses (copyleft, GPL, etc.)
```sql
SELECT p.name, p.version, l.license_id, m.display_path
FROM report_packages p
JOIN report_licenses l ON p.id = l.report_package_licenses
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
WHERE l.license_id LIKE '%GPL%' 
   OR l.license_id LIKE '%AGPL%' 
   OR l.license_id LIKE '%LGPL%'
   OR l.license_id LIKE '%Copyleft%'
ORDER BY l.license_id, p.name;
```

### Find packages flagged as malware
```sql
SELECT p.name, p.version, p.ecosystem, m.display_path
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
WHERE p.is_malware = 1;
```

### Find suspicious packages
```sql
SELECT p.name, p.version, p.ecosystem, m.display_path
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
WHERE p.is_suspicious = 1;
```

### Get malware analysis details
```sql
SELECT p.name, p.version, ma.analysis_id, ma.is_malware, ma.confidence
FROM report_packages p
JOIN report_malwares ma ON p.id = ma.report_package_malware_analysis
WHERE ma.is_malware = 1;
```

## Dependency Analysis Queries

### Find packages with dependencies
```sql
SELECT p.name, p.version, COUNT(d.id) as dependency_count
FROM report_packages p
LEFT JOIN report_dependencies d ON p.id = d.report_package_dependencies
GROUP BY p.id, p.name, p.version
HAVING dependency_count > 0
ORDER BY dependency_count DESC;
```

### Show dependency relationships
```sql
SELECT 
    parent.name as parent_package,
    parent.version as parent_version,
    d.dependency_name,
    d.dependency_version,
    d.dependency_ecosystem
FROM report_packages parent
JOIN report_dependencies d ON parent.id = d.report_package_dependencies
ORDER BY parent.name, d.dependency_name;
```

## Ecosystem Analysis Queries

### Count packages by ecosystem
```sql
SELECT ecosystem, COUNT(*) as package_count
FROM report_packages
GROUP BY ecosystem
ORDER BY package_count DESC;
```

### Find npm packages only
```sql
SELECT name, version, is_direct
FROM report_packages
WHERE ecosystem = 'npm'
ORDER BY name;
```

## Cross-Manifest Analysis Queries

### Find packages used across multiple manifests
```sql
SELECT p.name, p.version, p.ecosystem, COUNT(DISTINCT mp.report_package_manifest_id) as manifest_count
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
GROUP BY p.name, p.version, p.ecosystem
HAVING manifest_count > 1
ORDER BY manifest_count DESC;
```

### Compare direct dependencies across manifests
```sql
SELECT 
    m.display_path,
    p.name,
    p.version,
    p.ecosystem
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
WHERE p.is_direct = 1
ORDER BY m.display_path, p.name;
```

## OSS Project and OpenSSF Scorecard Queries

### Find packages with project information
```sql
SELECT p.name, p.version, proj.name as project_name, proj.url, proj.stars, proj.forks
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects
ORDER BY proj.stars DESC;
```

### Find packages with low scorecard scores
```sql
SELECT p.name, p.version, s.score, s.scorecard_version, proj.name as project_name
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects
JOIN report_scorecards s ON proj.id = s.report_project_scorecard
WHERE s.score < 5.0
ORDER BY s.score ASC;
```

### Find packages failing specific scorecard checks
```sql
SELECT p.name, p.version, c.name as check_name, c.score, c.reason, proj.name as project_name
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects  
JOIN report_scorecards s ON proj.id = s.report_project_scorecard
JOIN report_scorecard_checks c ON s.id = c.report_scorecard_checks
WHERE c.name = 'Maintained' AND c.score < 5
ORDER BY c.score ASC;
```

### OpenSSF scorecard check summary
```sql
SELECT 
    c.name as check_name,
    AVG(c.score) as avg_score,
    MIN(c.score) as min_score,
    MAX(c.score) as max_score,
    COUNT(*) as package_count
FROM report_scorecard_checks c
GROUP BY c.name
ORDER BY avg_score ASC;
```

### Find packages with security-related scorecard failures
```sql
SELECT DISTINCT p.name, p.version, c.name as failed_check, c.score, c.reason
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects  
JOIN report_scorecards s ON proj.id = s.report_project_scorecard
JOIN report_scorecard_checks c ON s.id = c.report_scorecard_checks
WHERE c.name IN ('Security-Policy', 'Vulnerabilities', 'Token-Permissions', 'Dangerous-Workflow')
  AND c.score < 5
ORDER BY c.score ASC;
```

### Find popular projects with poor security scores
```sql
SELECT 
    p.name, 
    p.version, 
    proj.name as project_name,
    proj.stars,
    s.score as scorecard_score,
    COUNT(c.id) as failed_checks
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects
JOIN report_scorecards s ON proj.id = s.report_project_scorecard
LEFT JOIN report_scorecard_checks c ON s.id = c.report_scorecard_checks AND c.score < 5
WHERE proj.stars > 1000 AND s.score < 6
GROUP BY p.id, proj.id, s.id
ORDER BY proj.stars DESC;
```

### Scorecard overview by ecosystem
```sql
SELECT 
    p.ecosystem,
    COUNT(DISTINCT p.id) as packages_with_scorecard,
    AVG(s.score) as avg_scorecard_score,
    MIN(s.score) as min_score,
    MAX(s.score) as max_score,
    AVG(proj.stars) as avg_stars
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects
JOIN report_scorecards s ON proj.id = s.report_project_scorecard
GROUP BY p.ecosystem
ORDER BY avg_scorecard_score DESC;
```

### Find packages with both vulnerabilities and poor scorecard scores
```sql
SELECT 
    p.name, 
    p.version,
    s.score as scorecard_score,
    COUNT(v.id) as vulnerability_count,
    SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_vulns,
    proj.name as project_name,
    proj.stars
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects
JOIN report_scorecards s ON proj.id = s.report_project_scorecard
LEFT JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
WHERE s.score < 6
GROUP BY p.id, proj.id, s.id
HAVING vulnerability_count > 0
ORDER BY critical_vulns DESC, vulnerability_count DESC;
```

### Detailed scorecard check analysis
```sql
SELECT 
    p.name,
    p.version,
    proj.name as project_name,
    s.score as overall_score,
    c.name as check_name,
    c.score as check_score,
    c.reason
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects
JOIN report_scorecards s ON proj.id = s.report_project_scorecard
JOIN report_scorecard_checks c ON s.id = c.report_scorecard_checks
WHERE p.name = 'example-package'
ORDER BY c.score ASC;
```

### Find projects with best security practices
```sql
SELECT 
    p.name,
    p.version,
    proj.name as project_name,
    proj.url,
    s.score as scorecard_score,
    proj.stars,
    proj.forks
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects
JOIN report_scorecards s ON proj.id = s.report_project_scorecard
WHERE s.score >= 8.0
ORDER BY s.score DESC, proj.stars DESC;
```

## SLSA Provenance Queries

### Find packages WITH SLSA provenance
```sql
SELECT p.name, p.version, p.ecosystem, COUNT(slsa.id) as provenance_count
FROM report_packages p
JOIN report_slsa_provenances slsa ON p.id = slsa.report_package_slsa_provenances
GROUP BY p.id, p.name, p.version, p.ecosystem
ORDER BY provenance_count DESC;
```

### Find packages WITHOUT SLSA provenance (Missing Supply Chain Security)
```sql
SELECT p.name, p.version, p.ecosystem, m.display_path
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
LEFT JOIN report_slsa_provenances slsa ON p.id = slsa.report_package_slsa_provenances
WHERE slsa.id IS NULL
ORDER BY p.name;
```

### Find packages with verified SLSA provenance
```sql
SELECT p.name, p.version, slsa.source_repository, slsa.commit_sha, slsa.url
FROM report_packages p
JOIN report_slsa_provenances slsa ON p.id = slsa.report_package_slsa_provenances
WHERE slsa.verified = true
ORDER BY p.name;
```

### Find packages with unverified SLSA provenance (Security Risk)
```sql
SELECT p.name, p.version, slsa.source_repository, slsa.commit_sha, slsa.verified
FROM report_packages p
JOIN report_slsa_provenances slsa ON p.id = slsa.report_package_slsa_provenances
WHERE slsa.verified = false
ORDER BY p.name;
```

### SLSA provenance summary by ecosystem
```sql
SELECT 
    p.ecosystem,
    COUNT(DISTINCT p.id) as total_packages,
    COUNT(DISTINCT CASE WHEN slsa.id IS NOT NULL THEN p.id END) as packages_with_provenance,
    COUNT(DISTINCT CASE WHEN slsa.verified = true THEN p.id END) as packages_with_verified_provenance,
    ROUND(
        (COUNT(DISTINCT CASE WHEN slsa.id IS NOT NULL THEN p.id END) * 100.0) / COUNT(DISTINCT p.id), 2
    ) as provenance_coverage_percent,
    ROUND(
        (COUNT(DISTINCT CASE WHEN slsa.verified = true THEN p.id END) * 100.0) / COUNT(DISTINCT p.id), 2
    ) as verified_provenance_percent
FROM report_packages p
LEFT JOIN report_slsa_provenances slsa ON p.id = slsa.report_package_slsa_provenances
GROUP BY p.ecosystem
ORDER BY provenance_coverage_percent DESC;
```

### Find direct dependencies without SLSA provenance (High Priority Security Risk)
```sql
SELECT p.name, p.version, p.ecosystem, m.display_path
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
LEFT JOIN report_slsa_provenances slsa ON p.id = slsa.report_package_slsa_provenances
WHERE p.is_direct = 1 AND slsa.id IS NULL
ORDER BY p.ecosystem, p.name;
```

### SLSA provenance source repository analysis
```sql
SELECT 
    slsa.source_repository,
    COUNT(DISTINCT p.id) as package_count,
    COUNT(CASE WHEN slsa.verified = true THEN 1 END) as verified_count,
    COUNT(CASE WHEN slsa.verified = false THEN 1 END) as unverified_count,
    GROUP_CONCAT(DISTINCT p.name) as packages
FROM report_slsa_provenances slsa
JOIN report_packages p ON slsa.report_package_slsa_provenances = p.id
GROUP BY slsa.source_repository
ORDER BY package_count DESC;
```

### Combined security analysis: Vulnerabilities + Missing SLSA Provenance
```sql
SELECT 
    p.name,
    p.version,
    p.ecosystem,
    COUNT(v.id) as vulnerability_count,
    CASE WHEN slsa.id IS NULL THEN 'Missing' ELSE 'Present' END as slsa_provenance,
    CASE WHEN slsa.verified = true THEN 'Verified' 
         WHEN slsa.verified = false THEN 'Unverified' 
         ELSE 'Missing' END as slsa_status,
    SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_vulns
FROM report_packages p
LEFT JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
LEFT JOIN report_slsa_provenances slsa ON p.id = slsa.report_package_slsa_provenances
GROUP BY p.id, p.name, p.version, p.ecosystem, slsa.id, slsa.verified
HAVING vulnerability_count > 0 OR slsa_provenance = 'Missing'
ORDER BY critical_vulns DESC, vulnerability_count DESC;
```

### Supply chain security scorecard
```sql
SELECT 
    m.display_path,
    COUNT(DISTINCT p.id) as total_packages,
    COUNT(DISTINCT CASE WHEN slsa.id IS NOT NULL THEN p.id END) as with_slsa_provenance,
    COUNT(DISTINCT CASE WHEN slsa.verified = true THEN p.id END) as with_verified_slsa,
    COUNT(DISTINCT CASE WHEN v.id IS NOT NULL THEN p.id END) as with_vulnerabilities,
    COUNT(DISTINCT CASE WHEN p.is_malware = 1 THEN p.id END) as malware_packages,
    ROUND(
        (COUNT(DISTINCT CASE WHEN slsa.verified = true THEN p.id END) * 100.0) / COUNT(DISTINCT p.id), 2
    ) as supply_chain_security_score
FROM report_package_manifests m
LEFT JOIN report_package_manifest_packages mp ON m.id = mp.report_package_manifest_id
LEFT JOIN report_packages p ON mp.report_package_id = p.id
LEFT JOIN report_slsa_provenances slsa ON p.id = slsa.report_package_slsa_provenances
LEFT JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
GROUP BY m.id, m.display_path
ORDER BY supply_chain_security_score DESC;
```

## Insights V2 Data Queries

### Query packages with Insights V2 data
```sql
SELECT name, version, ecosystem, 
       json_extract(insights_v2, '$.deprecated') as is_deprecated
FROM report_packages
WHERE insights_v2 IS NOT NULL;
```

### Extract vulnerability data from Insights V2
```sql
SELECT 
    name, 
    version,
    json_extract(insights_v2, '$.vulnerabilities') as vulnerabilities
FROM report_packages
WHERE json_extract(insights_v2, '$.vulnerabilities') IS NOT NULL;
```

## Vulnerability Analysis Queries

### Vulnerability summary by manifest
```sql
SELECT 
    m.display_path,
    m.ecosystem,
    COUNT(DISTINCT p.id) as total_packages,
    COUNT(v.id) as total_vulnerabilities,
    SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_vulns,
    SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_vulns,
    SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_vulns,
    SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END) as low_vulns
FROM report_package_manifests m
LEFT JOIN report_package_manifest_packages mp ON m.id = mp.report_package_manifest_id
LEFT JOIN report_packages p ON mp.report_package_id = p.id
LEFT JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
GROUP BY m.id, m.display_path, m.ecosystem
ORDER BY critical_vulns DESC, high_vulns DESC;
```

### Vulnerability timeline analysis
```sql
SELECT 
    DATE(v.created_at) as scan_date,
    v.severity,
    COUNT(*) as vulnerability_count
FROM report_vulnerabilities v
GROUP BY DATE(v.created_at), v.severity
ORDER BY scan_date DESC, v.severity;
```

### Extract vulnerability data from Insights v2 JSON
```sql
SELECT 
    p.name,
    p.version,
    json_extract(p.insights_v2, '$.vulnerabilities') as raw_vulnerabilities
FROM report_packages p
WHERE json_extract(p.insights_v2, '$.vulnerabilities') IS NOT NULL;
```

### Extract license data from Insights v2 JSON
```sql
SELECT 
    p.name,
    p.version,
    json_extract(p.insights_v2, '$.licenses') as raw_licenses
FROM report_packages p
WHERE json_extract(p.insights_v2, '$.licenses') IS NOT NULL;
```

### Combined security and license risk analysis
```sql
SELECT 
    p.name,
    p.version,
    COUNT(DISTINCT v.id) as vulnerability_count,
    GROUP_CONCAT(DISTINCT l.license_id) as licenses,
    SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_vulns,
    SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_vulns
FROM report_packages p
LEFT JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
LEFT JOIN report_licenses l ON p.id = l.report_package_licenses
GROUP BY p.id, p.name, p.version
HAVING vulnerability_count > 0 OR licenses IS NOT NULL
ORDER BY critical_vulns DESC, high_vulns DESC, vulnerability_count DESC;
```

## Advanced Analysis Queries

### Security risk overview by manifest
```sql
SELECT 
    m.display_path,
    m.ecosystem,
    COUNT(p.id) as total_packages,
    SUM(CASE WHEN p.is_malware = 1 THEN 1 ELSE 0 END) as malware_count,
    SUM(CASE WHEN p.is_suspicious = 1 THEN 1 ELSE 0 END) as suspicious_count,
    SUM(CASE WHEN p.is_direct = 1 THEN 1 ELSE 0 END) as direct_deps
FROM report_package_manifests m
LEFT JOIN report_package_manifest_packages mp ON m.id = mp.report_package_manifest_id
LEFT JOIN report_packages p ON mp.report_package_id = p.id
GROUP BY m.id, m.display_path, m.ecosystem
ORDER BY malware_count DESC, suspicious_count DESC;
```

### Generate package inventory report
```sql
SELECT 
    p.ecosystem,
    p.name,
    p.version,
    p.is_direct,
    p.package_url,
    m.display_path as found_in_manifest,
    p.created_at
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id
ORDER BY p.ecosystem, p.name, m.display_path;
```

## Working with JSON Data

Since some fields store JSON data, you can use SQLite's JSON functions to query nested data:

### Extract specific fields from package details
```sql
SELECT 
    name,
    version,
    json_extract(package_details, '$.commit') as commit_hash,
    json_extract(package_details, '$.ecosystem') as detail_ecosystem
FROM report_packages
WHERE package_details IS NOT NULL;
```

### Query code analysis data
```sql
SELECT 
    name,
    version,
    json_extract(code_analysis, '$.usage_evidences') as usage_evidences
FROM report_packages
WHERE code_analysis IS NOT NULL;
```

## Tips for Querying

1. **Use EXPLAIN QUERY PLAN** to optimize slow queries
2. **Create indexes** on frequently queried columns for better performance
3. **Use JSON functions** to extract data from JSON fields
4. **Join tables** to get comprehensive views across related data
5. **Use aggregate functions** to generate summary statistics

## Dependency Graph Analysis Queries

The SQLite3 reporter includes a comprehensive dependency graph stored in the `report_dependency_graphs` table, enabling advanced dependency analysis including path tracing, dependent discovery, and graph traversal queries.

### Dependency Graph Schema

The dependency graph is stored in the `report_dependency_graphs` table with the following structure:

```sql
CREATE TABLE report_dependency_graphs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    -- Source package (dependent)
    from_package_id TEXT NOT NULL,
    from_package_name TEXT NOT NULL,
    from_package_version TEXT NOT NULL,
    from_package_ecosystem TEXT NOT NULL,
    
    -- Target package (dependency)
    to_package_id TEXT NOT NULL,
    to_package_name TEXT NOT NULL,
    to_package_version TEXT NOT NULL,
    to_package_ecosystem TEXT NOT NULL,
    
    -- Edge metadata
    dependency_type TEXT,
    version_constraint TEXT,
    depth INTEGER DEFAULT 0,
    is_direct BOOLEAN DEFAULT FALSE,
    is_root_edge BOOLEAN DEFAULT FALSE,
    manifest_id TEXT NOT NULL,
    
    created_at DATETIME,
    updated_at DATETIME
);
```

### Find All Dependencies of a Package

```sql
SELECT 
    to_package_name,
    to_package_version,
    to_package_ecosystem,
    depth,
    is_direct,
    dependency_type
FROM report_dependency_graphs 
WHERE from_package_name = 'express' 
  AND from_package_ecosystem = 'npm'
ORDER BY depth, to_package_name;
```

### Find All Dependents of a Package

```sql
SELECT 
    from_package_name,
    from_package_version,
    from_package_ecosystem,
    depth,
    is_direct
FROM report_dependency_graphs 
WHERE to_package_name = 'lodash' 
  AND to_package_ecosystem = 'npm'
ORDER BY depth, from_package_name;
```

### Find Direct Dependencies Only

```sql
SELECT 
    to_package_name,
    to_package_version,
    to_package_ecosystem,
    dependency_type
FROM report_dependency_graphs 
WHERE from_package_name = 'my-app' 
  AND is_direct = 1
ORDER BY to_package_name;
```

### Find Root Packages (Top-Level Dependencies)

```sql
SELECT DISTINCT
    from_package_name,
    from_package_version,
    from_package_ecosystem,
    manifest_id
FROM report_dependency_graphs 
WHERE is_root_edge = 1
ORDER BY from_package_name;
```

### Trace Dependency Path (Simple Path from A to B)

```sql
WITH RECURSIVE dependency_path AS (
    -- Base case: find direct dependencies
    SELECT 
        from_package_id,
        from_package_name,
        to_package_id,
        to_package_name,
        depth,
        from_package_name || ' -> ' || to_package_name AS path,
        1 AS level
    FROM report_dependency_graphs 
    WHERE from_package_name = 'my-app'
    
    UNION ALL
    
    -- Recursive case: follow the dependency chain
    SELECT 
        rdg.from_package_id,
        rdg.from_package_name,
        rdg.to_package_id,
        rdg.to_package_name,
        rdg.depth,
        dp.path || ' -> ' || rdg.to_package_name,
        dp.level + 1
    FROM report_dependency_graphs rdg
    JOIN dependency_path dp ON rdg.from_package_id = dp.to_package_id
    WHERE dp.level < 10 -- Prevent infinite loops
)
SELECT path, level 
FROM dependency_path
WHERE to_package_name = 'target-package'
ORDER BY level;
```

### Find Packages with Vulnerabilities in Dependency Chain

```sql
SELECT DISTINCT
    dg.from_package_name,
    dg.from_package_version,
    dg.to_package_name AS vulnerable_dep,
    dg.to_package_version AS vulnerable_version,
    rv.vulnerability_id,
    rv.severity,
    dg.depth
FROM report_dependency_graphs dg
JOIN report_packages rp ON dg.to_package_id = rp.package_id
JOIN report_vulnerabilities rv ON rp.id = rv.report_package_vulnerabilities
WHERE dg.from_package_name = 'my-app'
  AND rv.severity IN ('CRITICAL', 'HIGH')
ORDER BY dg.depth, rv.severity;
```

### Find Dependency Depth Distribution

```sql
SELECT 
    depth,
    COUNT(*) as edge_count,
    COUNT(DISTINCT to_package_name) as unique_packages
FROM report_dependency_graphs
GROUP BY depth
ORDER BY depth;
```

### Find Packages with Most Dependencies

```sql
SELECT 
    from_package_name,
    from_package_version,
    from_package_ecosystem,
    COUNT(*) as dependency_count
FROM report_dependency_graphs
GROUP BY from_package_id, from_package_name, from_package_version, from_package_ecosystem
ORDER BY dependency_count DESC
LIMIT 10;
```

### Find Packages with Most Dependents

```sql
SELECT 
    to_package_name,
    to_package_version,
    to_package_ecosystem,
    COUNT(*) as dependent_count
FROM report_dependency_graphs
GROUP BY to_package_id, to_package_name, to_package_version, to_package_ecosystem
ORDER BY dependent_count DESC
LIMIT 10;
```

### Find Circular Dependencies

```sql
WITH RECURSIVE circular_deps AS (
    SELECT 
        from_package_id,
        to_package_id,
        from_package_name,
        to_package_name,
        from_package_name || ' -> ' || to_package_name AS path,
        1 AS level
    FROM report_dependency_graphs
    
    UNION ALL
    
    SELECT 
        rdg.from_package_id,
        rdg.to_package_id,
        rdg.from_package_name,
        rdg.to_package_name,
        cd.path || ' -> ' || rdg.to_package_name,
        cd.level + 1
    FROM report_dependency_graphs rdg
    JOIN circular_deps cd ON rdg.from_package_id = cd.to_package_id
    WHERE cd.level < 50
    AND rdg.to_package_id NOT IN (
        SELECT from_package_id 
        FROM circular_deps c2 
        WHERE c2.path = cd.path
    )
)
SELECT path
FROM circular_deps
WHERE to_package_id = from_package_id
ORDER BY level;
```

### Complex Vulnerability Impact Analysis

```sql
-- Find all packages that depend on packages with high severity vulnerabilities
SELECT DISTINCT
    root_pkg.from_package_name as root_package,
    vuln_pkg.to_package_name as vulnerable_package,
    rv.vulnerability_id,
    rv.severity,
    MIN(dg.depth) as min_depth
FROM report_dependency_graphs root_pkg
JOIN report_dependency_graphs dg ON root_pkg.from_package_id = dg.from_package_id
JOIN report_packages rp ON dg.to_package_id = rp.package_id
JOIN report_vulnerabilities rv ON rp.id = rv.report_package_vulnerabilities
JOIN report_dependency_graphs vuln_pkg ON dg.to_package_id = vuln_pkg.to_package_id
WHERE root_pkg.is_root_edge = 1
  AND rv.severity IN ('CRITICAL', 'HIGH')
GROUP BY root_pkg.from_package_name, vuln_pkg.to_package_name, rv.vulnerability_id
ORDER BY min_depth, rv.severity;
```

### Find Transitive Dependency Chains

```sql
SELECT 
    dg1.from_package_name as root_pkg,
    dg1.to_package_name as direct_dep,
    dg2.to_package_name as transitive_dep,
    dg1.depth + dg2.depth as total_depth
FROM report_dependency_graphs dg1 
JOIN report_dependency_graphs dg2 ON dg1.to_package_id = dg2.from_package_id
WHERE dg1.is_root_edge = 1 AND dg2.depth > 0
ORDER BY total_depth
LIMIT 10;
```

### Vulnerability Impact Summary

```sql
SELECT 
    rp.name as vulnerable_package,
    rv.vulnerability_id,
    rv.severity,
    COUNT(dg.from_package_id) as packages_affected
FROM report_packages rp
JOIN report_vulnerabilities rv ON rp.id = rv.report_package_vulnerabilities
LEFT JOIN report_dependency_graphs dg ON rp.package_id = dg.to_package_id
GROUP BY rp.package_id, rv.vulnerability_id
ORDER BY rv.severity, packages_affected DESC;
```

### Performance Optimization

The dependency graph queries are optimized with the following indexes:

- `from_package_id` - for finding dependencies
- `to_package_id` - for finding dependents  
- `manifest_id` - for manifest-specific queries
- `is_direct` - for direct dependency queries
- `is_root_edge` - for root package queries
- `depth` - for depth-based queries

For large dependency graphs, consider:
- Using LIMIT clauses for exploratory queries
- Adding WHERE clauses to filter by ecosystem or manifest
- Using the depth field to limit traversal depth
- Creating additional indexes for frequently queried patterns

## OpenSSF Scorecard Database Schema

The OpenSSF scorecard data is stored in separate, normalized entities for optimal querying:

### ReportProjects Table
```sql
CREATE TABLE report_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT,
    description TEXT,
    stars INTEGER,
    forks INTEGER,
    created_at DATETIME,
    updated_at DATETIME,
    report_package_projects INTEGER REFERENCES report_packages(id)
);
```

### ReportScorecards Table
```sql
CREATE TABLE report_scorecards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    score REAL NOT NULL,
    scorecard_version TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    repo_commit TEXT NOT NULL,
    date TEXT,
    created_at DATETIME,
    updated_at DATETIME,
    report_project_scorecard INTEGER REFERENCES report_projects(id)
);
```

### ReportScorecardChecks Table
```sql
CREATE TABLE report_scorecard_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    score REAL NOT NULL,
    reason TEXT,
    created_at DATETIME,
    updated_at DATETIME,
    report_scorecard_checks INTEGER REFERENCES report_scorecards(id)
);
```

### ReportSlsaProvenances Table
```sql
CREATE TABLE report_slsa_provenances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_repository TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    url TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME,
    updated_at DATETIME,
    report_package_slsa_provenances INTEGER REFERENCES report_packages(id)
);
```

This normalized schema enables:
- Direct queries on scorecard scores without JSON parsing
- Individual analysis of each scorecard check
- Efficient joins across packages → projects → scorecards → checks
- **SLSA provenance tracking** for supply chain security analysis
- **Verification status monitoring** to identify unverified provenance
- **Source repository analysis** to understand package origins
- Proper indexing on scorecard and provenance fields for performance

## Creating Views for Common Queries

You can create views to simplify frequently used queries:

```sql
-- Create a view for security overview
CREATE VIEW security_overview AS
SELECT 
    p.name,
    p.version,
    p.ecosystem,
    p.is_direct,
    p.is_malware,
    p.is_suspicious,
    m.display_path,
    m.ecosystem as manifest_ecosystem
FROM report_packages p
JOIN report_package_manifest_packages mp ON p.id = mp.report_package_id
JOIN report_package_manifests m ON mp.report_package_manifest_id = m.id;

-- Create a view for vulnerability impact analysis
CREATE VIEW vulnerability_impact AS
SELECT 
    rp.name as vulnerable_package,
    rp.version as vulnerable_version,
    rv.vulnerability_id,
    rv.severity,
    dg.from_package_name as affected_package,
    dg.depth as dependency_depth,
    dg.is_direct,
    dg.is_root_edge
FROM report_packages rp
JOIN report_vulnerabilities rv ON rp.id = rv.report_package_vulnerabilities
LEFT JOIN report_dependency_graphs dg ON rp.package_id = dg.to_package_id;

-- Create a view for scorecard analysis
CREATE VIEW scorecard_analysis AS
SELECT 
    p.name as package_name,
    p.version as package_version,
    p.ecosystem,
    proj.name as project_name,
    proj.url as project_url,
    proj.stars,
    proj.forks,
    s.score as scorecard_score,
    s.scorecard_version,
    s.repo_name,
    s.date as scorecard_date
FROM report_packages p
JOIN report_projects proj ON p.id = proj.report_package_projects
LEFT JOIN report_scorecards s ON proj.id = s.report_project_scorecard;

-- Create a view for security posture overview
CREATE VIEW security_posture AS
SELECT 
    p.name,
    p.version,
    p.ecosystem,
    p.is_malware,
    p.is_suspicious,
    COUNT(DISTINCT v.id) as vulnerability_count,
    SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_vulns,
    SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_vulns,
    s.score as scorecard_score,
    proj.stars
FROM report_packages p
LEFT JOIN report_vulnerabilities v ON p.id = v.report_package_vulnerabilities
LEFT JOIN report_projects proj ON p.id = proj.report_package_projects
LEFT JOIN report_scorecards s ON proj.id = s.report_project_scorecard
GROUP BY p.id, proj.id, s.id;

-- Create a view for SLSA provenance analysis
CREATE VIEW slsa_provenance_analysis AS
SELECT 
    p.name as package_name,
    p.version as package_version,
    p.ecosystem,
    p.is_direct,
    slsa.source_repository,
    slsa.commit_sha,
    slsa.url as provenance_url,
    slsa.verified,
    CASE 
        WHEN slsa.id IS NULL THEN 'Missing'
        WHEN slsa.verified = true THEN 'Verified'
        ELSE 'Unverified'
    END as provenance_status
FROM report_packages p
LEFT JOIN report_slsa_provenances slsa ON p.id = slsa.report_package_slsa_provenances;

-- Use the views
SELECT * FROM security_overview WHERE is_malware = 1;
SELECT * FROM vulnerability_impact WHERE severity IN ('CRITICAL', 'HIGH');
SELECT * FROM scorecard_analysis WHERE scorecard_score < 5.0;
SELECT * FROM security_posture WHERE scorecard_score < 6 AND vulnerability_count > 0;
SELECT * FROM slsa_provenance_analysis WHERE provenance_status = 'Missing';
SELECT * FROM slsa_provenance_analysis WHERE is_direct = 1 AND provenance_status != 'Verified';
```