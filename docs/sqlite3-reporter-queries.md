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

-- Use the view
SELECT * FROM security_overview WHERE is_malware = 1;
```