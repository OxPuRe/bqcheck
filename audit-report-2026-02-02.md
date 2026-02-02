# BigQuery Audit Report - roam-staging-dt-cur-0

**Audit Date:** 2026-02-02
**Generated:** 2026-02-02T20:54:11.863616+00:00

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Recommendations | 10 |
| Potential Monthly Savings | €370.07 |
| High Priority | 0 |
| Medium Priority | 2 |
| Low Priority | 8 |

### Savings Breakdown by Category

| Category | Count | Monthly Savings |
|----------|-------|-----------------|
| Clustering | 0 | €0.00 |
| Partitioning | 0 | €0.00 |
| Queries | 0 | €0.00 |
| Storage | 10 | €370.07 |
| Temporal | 0 | €0.00 |

## Quick Wins

_No high-priority recommendations at this time._

## Detailed Recommendations

### Recommendation 1: Remove unused 9418GB table

**Type:** storage
**Priority:** MEDIUM
**Estimated Monthly Savings:** €211.53

**Description:**
Table geopersona.residents_visits_copy2 (9417.63 GB) has not been accessed for 489 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table geopersona.residents_visits_copy2 contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.residents_visits_copy2 && bq cp geopersona.residents_visits_copy2 backup_dataset.residents_visits_copy2
3. Delete table: DROP TABLE geopersona.residents_visits_copy2
4. Verify deletion and monitor for any application errors

---

### Recommendation 2: Remove unused 4520GB table

**Type:** storage
**Priority:** MEDIUM
**Estimated Monthly Savings:** €101.53

**Description:**
Table entities.stay_points_fr (4520.41 GB) has not been accessed for 187 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table entities.stay_points_fr contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.stay_points_fr && bq cp entities.stay_points_fr backup_dataset.stay_points_fr
3. Delete table: DROP TABLE entities.stay_points_fr
4. Verify deletion and monitor for any application errors

---

### Recommendation 3: Remove unused 1514GB table

**Type:** storage
**Priority:** LOW
**Estimated Monthly Savings:** €34.00

**Description:**
Table mobility.mobility_fr (1513.73 GB) has not been accessed for 187 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table mobility.mobility_fr contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.mobility_fr && bq cp mobility.mobility_fr backup_dataset.mobility_fr
3. Delete table: DROP TABLE mobility.mobility_fr
4. Verify deletion and monitor for any application errors

---

### Recommendation 4: Remove unused 554GB table

**Type:** storage
**Priority:** LOW
**Estimated Monthly Savings:** €12.45

**Description:**
Table user.user_home_work_quarterly (554.44 GB) has not been accessed for 420 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table user.user_home_work_quarterly contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.user_home_work_quarterly && bq cp user.user_home_work_quarterly backup_dataset.user_home_work_quarterly
3. Delete table: DROP TABLE user.user_home_work_quarterly
4. Verify deletion and monitor for any application errors

---

### Recommendation 5: Remove unused 332GB table

**Type:** storage
**Priority:** LOW
**Estimated Monthly Savings:** €7.46

**Description:**
Table mobility.mobility (331.95 GB) has not been accessed for 454 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table mobility.mobility contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.mobility && bq cp mobility.mobility backup_dataset.mobility
3. Delete table: DROP TABLE mobility.mobility
4. Verify deletion and monitor for any application errors

---

### Recommendation 6: Remove unused 59GB table

**Type:** storage
**Priority:** LOW
**Estimated Monthly Savings:** €1.33

**Description:**
Table outlogic_mask.outlogic_test_source (59.41 GB) has not been accessed for 283 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table outlogic_mask.outlogic_test_source contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.outlogic_test_source && bq cp outlogic_mask.outlogic_test_source backup_dataset.outlogic_test_source
3. Delete table: DROP TABLE outlogic_mask.outlogic_test_source
4. Verify deletion and monitor for any application errors

---

### Recommendation 7: Remove unused 29GB table

**Type:** storage
**Priority:** LOW
**Estimated Monthly Savings:** €0.66

**Description:**
Table sources.gfk_admin (29.21 GB) has not been accessed for 539 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table sources.gfk_admin contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.gfk_admin && bq cp sources.gfk_admin backup_dataset.gfk_admin
3. Delete table: DROP TABLE sources.gfk_admin
4. Verify deletion and monitor for any application errors

---

### Recommendation 8: Remove unused 23GB table

**Type:** storage
**Priority:** LOW
**Estimated Monthly Savings:** €0.52

**Description:**
Table user.user_attribute (23.20 GB) has not been accessed for 454 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table user.user_attribute contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.user_attribute && bq cp user.user_attribute backup_dataset.user_attribute
3. Delete table: DROP TABLE user.user_attribute
4. Verify deletion and monitor for any application errors

---

### Recommendation 9: Remove unused 15GB table

**Type:** storage
**Priority:** LOW
**Estimated Monthly Savings:** €0.34

**Description:**
Table referential.admin_boundaries (15.26 GB) has not been accessed for 474 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table referential.admin_boundaries contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.admin_boundaries && bq cp referential.admin_boundaries backup_dataset.admin_boundaries
3. Delete table: DROP TABLE referential.admin_boundaries
4. Verify deletion and monitor for any application errors

---

### Recommendation 10: Remove unused 11GB table

**Type:** storage
**Priority:** LOW
**Estimated Monthly Savings:** €0.25

**Description:**
Table user.home_work (11.09 GB) has not been accessed for 496 days. Consider deleting to save storage costs.

**Implementation Steps:**
1. Review table user.home_work contents and confirm it's no longer needed
2. Backup table if needed: bq mk --table backup_dataset.home_work && bq cp user.home_work backup_dataset.home_work
3. Delete table: DROP TABLE user.home_work
4. Verify deletion and monitor for any application errors

---


## Implementation Guidance

### Getting Started

1. **Prioritize High-Impact Changes**: Start with HIGH priority recommendations that offer the largest monthly savings
2. **Test in Non-Production**: Always test changes in a development or staging environment first
3. **Monitor Query Performance**: Use BigQuery's query execution details to validate improvements
4. **Backup Before Changes**: Create table snapshots before modifying partitioning or clustering

### Best Practices

- **Partitioning**: Implement date-based partitioning for time-series data to reduce scan costs
- **Clustering**: Add clustering keys for columns frequently used in WHERE and GROUP BY clauses
- **Storage Cleanup**: Schedule regular reviews of unused tables and datasets
- **Query Optimization**: Review and optimize queries identified as expensive or repetitive

### Need Help?

Refer to [BigQuery Best Practices](https://cloud.google.com/bigquery/docs/best-practices) for detailed guidance on implementing these recommendations.

