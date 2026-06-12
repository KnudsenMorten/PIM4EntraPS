# PIM activation use-cases — 100 just-in-time, approval-gated, audited scenarios

Pattern for every entry: a persona needs to perform a **sensitive action** in a
workload, so they **activate** an eligible PIM group (time-boxed, optionally
approval-required, fully audited) that grants the workload role; access expires
automatically afterward. The group → workload-role binding is what the
PIM4EntraPS workload connectors maintain (see WORKLOAD-CONNECTORS.md /
ENTRA-GROUP-APP-CATALOG.md).

## Finance / ERP (Business Central, Dynamics 365 Finance)
1. Finance controller edits the **chart of accounts / account plan** → activate BC `G/L Setup Manager`.
2. Post a manual journal / year-end closing entry → activate BC `Accountant`.
3. Change VAT/tax posting setup → activate BC `Tax Setup Manager`.
4. Modify payment/vendor bank details → activate BC `AP Manager` (approval-required).
5. Run a currency revaluation → activate BC `Finance Operator`.
6. Edit dimensions / cost centres → activate BC `Dimensions Manager`.
7. Approve a purchase order over threshold → activate D365 `Purchasing Approver`.
8. Adjust inventory valuation → activate D365 `Inventory Controller`.
9. Open a closed accounting period → activate BC `Period Control` (approval).
10. Export the general ledger for audit → activate BC `Audit Reader`.

## HR / People (Dynamics 365 HR, Workday, SuccessFactors)
11. HR manager **restructures the org layout / reporting lines** → activate `HR Org Designer`.
12. Edit compensation bands → activate `Comp & Benefits Admin` (approval).
13. Process terminations / offboarding → activate `HR Offboarding Operator`.
14. Bulk-edit job profiles → activate `HR Data Manager`.
15. Approve a promotion → activate `HR Approver`.
16. Run a payroll export → activate `Payroll Operator` (approval).
17. Edit sensitive personal data → activate `HR PII Editor` (approval, short TTL).
18. Configure performance-review cycles → activate `Talent Admin`.
19. Manage org positions in SuccessFactors → activate `Position Manager`.
20. Reorg a department in Workday → activate `Workday Org Admin` (approval).

## Security operations (Defender XDR, Sentinel, MDCA)
21. SecOps analyst runs a live response / isolates a device → activate Defender `Security Operations Operator`.
22. Tune detection rules → activate Defender `Security Posture Operator`.
23. Read incidents only → activate Defender `Security Operations Reader`.
24. Change Defender authorization/settings → activate Defender `Auth & Settings Admin` (approval).
25. Run advanced hunting at scale → activate Defender `Threat Hunter`.
26. Edit Sentinel analytics rules → activate Sentinel `Contributor`.
27. Run a Sentinel playbook → activate Sentinel `Responder`.
28. Manage MDCA policies → activate `Cloud App Security Admin`.
29. Approve a quarantine release → activate `Defender for Office Operator`.
30. Scope SecOps to servers only → activate `SecOps Operator (Servers scope)`.

## Endpoint management (Intune)
31. Push an emergency device config profile → activate Intune `Policy and Profile manager`.
32. Wipe / retire a lost device → activate Intune `Help Desk Operator`.
33. Deploy an app to all devices → activate Intune `Application Manager`.
34. Change endpoint security baselines → activate Intune `Endpoint Security Manager` (approval).
35. Read-only device inventory → activate Intune `Read Only Operator`.
36. Manage EPM elevation rules → activate Intune `Endpoint Privilege Manager`.
37. Configure Autopilot profiles → activate Intune `Policy and Profile manager`.
38. School/EDU device rollout → activate Intune `School Administrator`.
39. Approve a multi-admin policy change → activate Intune `Multi Admin Approval Policy Manager`.
40. Manage Intune RBAC itself → activate Intune `Intune Role Administrator` (approval).

## Identity (Entra ID directory roles)
41. Reset MFA for a VIP → activate `Authentication Administrator` (approval).
42. Create/edit an enterprise app → activate `Application Administrator`.
43. Manage Conditional Access → activate `Conditional Access Administrator` (approval).
44. Approve privileged role requests → activate `Privileged Role Administrator` (approval).
45. Read sign-in logs for an investigation → activate `Security Reader`.
46. Manage groups membership → activate `Groups Administrator`.
47. Restore a deleted user → activate `User Administrator`.
48. Manage named locations → activate `Conditional Access Administrator`.
49. Break-glass tenant action → activate `Global Administrator` (approval + short TTL).
50. Manage device registration → activate `Cloud Device Administrator`.

## Azure infrastructure (Azure RBAC)
51. Deploy to a production subscription → activate `Contributor` @ sub (approval).
52. Assign roles on a management group → activate `User Access Administrator` @ MG (approval).
53. Rotate a Key Vault secret → activate `Key Vault Secrets Officer`.
54. Restart a production VM → activate `Virtual Machine Contributor`.
55. Modify a landing-zone policy → activate `Resource Policy Contributor` (approval).
56. Read cost data → activate `Cost Management Reader`.
57. Manage AKS cluster RBAC → activate `Azure Kubernetes Service RBAC Admin`.
58. Configure networking on a hub VNet → activate `Network Contributor` (approval).
59. Owner at tenant root for a fix → activate `Owner` @ root MG (approval + short TTL).
60. Manage a storage account's data → activate `Storage Blob Data Owner`.

## Data & BI (Power BI / Fabric)
61. Publish to a production workspace → activate Power BI `Member`.
62. Admin a Fabric capacity → activate `Capacity Admin` (approval).
63. Edit a certified dataset → activate `Contributor`.
64. Manage tenant settings → activate `Power BI Administrator` (approval).
65. Read a sensitive report → activate `Viewer`.
66. Manage gateways → activate `Gateway Admin`.
67. Configure dataflows → activate `Contributor`.
68. Approve a workspace promotion → activate `Deployment Approver`.
69. Manage row-level security → activate `Dataset RLS Admin` (approval).
70. Export underlying data → activate `Data Export Operator`.

## Collaboration (Exchange, SharePoint, Teams, M365)
71. Grant a shared-mailbox delegation → activate Exchange `Recipient Admin`.
72. Run an eDiscovery search → activate Purview `eDiscovery Manager` (approval).
73. Edit a transport rule → activate Exchange `Transport Rules Admin` (approval).
74. Restore a deleted SharePoint site → activate `SharePoint Administrator`.
75. Manage a Team's membership/policies → activate `Teams Administrator`.
76. Configure retention policies → activate Purview `Retention Manager` (approval).
77. Manage sharing settings → activate `SharePoint Administrator`.
78. Approve a sensitivity-label change → activate Purview `Information Protection Admin`.
79. Run a content search → activate Purview `Compliance Operator`.
80. Manage Teams voice/calling → activate `Teams Communications Administrator`.

## DevOps & engineering (Azure DevOps, GitHub)
81. Manage org-level DevOps security → activate `Project Collection Administrator` (approval).
82. Edit a release pipeline → activate `Build Administrator`.
83. Manage repo branch policies → activate `Repo Administrator`.
84. Rotate a service connection → activate `Endpoint Administrator` (approval).
85. Admin a GitHub org → activate `GitHub Org Owner` (approval).
86. Manage Actions secrets → activate `GitHub Secrets Admin`.
87. Approve a production deploy → activate `Deployment Approver`.
88. Manage self-hosted runners → activate `Runner Administrator`.
89. Edit branch protection → activate `Repo Maintainer`.
90. Audit DevOps access → activate `DevOps Reader`.

## Third-party SaaS (SCIM/app-role group activation)
91. Salesforce: edit a critical flow → activate `SF System Administrator` (approval).
92. ServiceNow: edit a business rule → activate `SNOW Admin` (approval).
93. AWS: assume a prod admin role → activate `AWS Admin` permission set (approval).
94. Snowflake: alter a warehouse → activate `Snowflake SYSADMIN`.
95. Databricks: manage a workspace → activate `Databricks Admin`.
96. Zoom: change account settings → activate `Zoom Admin`.
97. Atlassian: edit Jira workflow → activate `Jira Administrator` (approval).
98. Box: change enterprise settings → activate `Box Co-Admin`.
99. Workday: integration config → activate `Workday ISU Admin` (approval).
100. Adobe: manage license assignments → activate `Adobe System Admin`.

---

Common thread: each is **eligible** (not standing), activated **just-in-time** with
**approval** on the high-impact ones, bounded by a **short TTL**, and **audited** end
to end. PIM4EntraPS provisions the groups + binds them to the workload roles (via the
connector for RBAC-API workloads, or app-role/SCIM for the rest); native Entra PIM
governs the activation + approval at use time.
