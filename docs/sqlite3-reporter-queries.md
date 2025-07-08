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
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id
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
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id
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
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id
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
LEFT JOIN report_packages p ON m.id = p.report_package_manifest_packages
LEFT JOIN report_licenses l ON p.id = l.report_package_licenses
GROUP BY m.id, m.display_path
ORDER BY unique_licenses DESC;
```

### Find packages without license information
```sql
SELECT p.name, p.version, p.ecosystem, m.display_path
FROM report_packages p
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id
LEFT JOIN report_licenses l ON p.id = l.report_package_licenses
WHERE l.id IS NULL;
```

### Find potentially problematic licenses (copyleft, GPL, etc.)
```sql
SELECT p.name, p.version, l.license_id, m.display_path
FROM report_packages p
JOIN report_licenses l ON p.id = l.report_package_licenses
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id
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
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id
WHERE p.is_malware = 1;
```

### Find suspicious packages
```sql
SELECT p.name, p.version, p.ecosystem, m.display_path
FROM report_packages p
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id
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
SELECT p.name, p.version, p.ecosystem, COUNT(DISTINCT p.report_package_manifest_packages) as manifest_count
FROM report_packages p
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
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id
WHERE p.is_direct = 1
ORDER BY m.display_path, p.name;
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
LEFT JOIN report_packages p ON m.id = p.report_package_manifest_packages
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
LEFT JOIN report_packages p ON m.id = p.report_package_manifest_packages
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
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id
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
JOIN report_package_manifests m ON p.report_package_manifest_packages = m.id;

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

-- Use the views
SELECT * FROM security_overview WHERE is_malware = 1;
SELECT * FROM vulnerability_impact WHERE severity IN ('CRITICAL', 'HIGH');
```