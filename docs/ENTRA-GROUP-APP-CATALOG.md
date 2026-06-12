# Entra-group app catalog — what a PIM/Entra group can target, and how

Purpose: catalog the Microsoft-native workloads and common third-party apps that
consume **Entra (Azure AD) security groups** for access/RBAC, classified by the
*mechanism* — because that determines whether PIM4EntraPS reaches them via a
**workload connector** (queryable role API), or via **standard Entra** (enterprise-app
app-role assignment, SCIM provisioning, group claims, or group-based licensing).

## Integration mechanisms (legend)
- **RBAC-API** — the app exposes a role API where a group is assigned to a role → a **PIM4EntraPS workload connector** applies (build a `*.connector.json`).
- **AppRole** — assign the group to an enterprise-app *app role* (Graph `appRoleAssignedTo`) → generic; one connector pattern fits all.
- **SCIM** — Entra provisions the group + members into the app (SCIM 2.0) → governed by the provisioning job, not a role API.
- **Claim** — the app reads group membership from the token (groups/role claim) → assignment = add to the group.
- **License** — group-based licensing drives access.

Status: ✅ connector built · ◑ connector-eligible (RBAC-API, not yet built) · ○ standard Entra (AppRole/SCIM/Claim/License)

---

## A. Microsoft native workloads (RBAC-API / role-based)
1. Entra ID directory roles — RBAC-API ◑ (`/roleManagement/directory`)
2. Azure RBAC (MG/sub/RG/resource) — RBAC-API ◑ (ARM; needs ARM auth adapter)
3. Microsoft Intune — RBAC-API ✅ (`intune`)
4. Microsoft Defender XDR (Unified RBAC) — RBAC-API ✅ (`defender-xdr`)
5. Microsoft Defender for Cloud — RBAC-API ◑ (Azure RBAC)
6. Microsoft Sentinel — RBAC-API ◑ (Azure RBAC)
7. Microsoft Purview (compliance/DLP/eDiscovery roles) — RBAC-API ◑
8. Microsoft Defender for Cloud Apps (MDCA) — RBAC-API ◑
9. Microsoft Defender for Identity — RBAC-API ◑
10. Microsoft Defender for Endpoint — RBAC-API ◑ (device-group scoping)
11. Power BI / Microsoft Fabric (workspace roles + admin) — RBAC-API ◑ (Power BI auth adapter)
12. Power Platform (environment roles, admin) — RBAC-API ◑
13. Power Apps / Power Automate — RBAC-API ◑
14. Dynamics 365 (security roles) — RBAC-API ◑ (Dataverse)
15. Dataverse (security roles / teams) — RBAC-API ◑ (per-environment app user)
16. Business Central (permission sets / security groups) — RBAC-API ◑ (per-env)
17. Azure DevOps (org/project security groups) — RBAC-API ◑ (vssps auth adapter)
18. Exchange Online (RBAC role groups) — RBAC-API ◑ (EXO management)
19. SharePoint Online (admin role; site groups) — AppRole/Claim ○ + Entra role
20. Microsoft Teams (Teams admin roles = Entra roles; team membership) — Claim ○
21. Microsoft 365 admin roles — RBAC-API ◑ (Entra directory roles)
22. Azure SQL / SQL MI (Entra-only auth, group logins) — Claim ○
23. Azure Kubernetes Service (Entra group RBAC) — Claim ○ (k8s RoleBinding)
24. Azure Key Vault / Storage / App Config (RBAC) — RBAC-API ◑ (Azure RBAC)
25. Windows 365 / Cloud PC (provisioning + admin) — License/Claim ○
26. Microsoft Entra Permissions Management — RBAC-API ◑
27. Microsoft Viva (Engage/Insights/Learning admin) — Claim ○
28. Microsoft Stream / Forms / Bookings / Planner / Project / Visio — License ○
29. Windows Autopilot / device groups — Claim ○ (dynamic/assigned groups)
30. Conditional Access targeting (group-scoped policies) — Claim ○

## B. Microsoft 365 group-driven access (License/Claim)
31. M365 group-based licensing  32. SharePoint sites  33. OneDrive  34. Teams membership
35. Viva Engage (Yammer)  36. Planner  37. Loop  38. Whiteboard  39. Stream
40. Bookings  41. Forms  42. Copilot for M365 (licensing)  43. Outlook/EXO shared mailboxes
44. Microsoft To Do / Lists  45. Project for the web  46. Power Pages  47. Clipchamp
48. Microsoft Places  49. Viva Goals  50. Viva Learning

## C. Common third-party SaaS integrating with Entra groups (AppRole / SCIM / Claim)
51. Salesforce — SCIM/AppRole  52. ServiceNow — SCIM/Claim  53. Workday — SCIM
54. SAP SuccessFactors — SCIM  55. SAP Cloud Identity — SCIM  56. SAP Concur — AppRole
57. SAP Ariba — AppRole  58. Slack — SCIM  59. Zoom — SCIM  60. Cisco Webex — SCIM
61. Atlassian Jira — SCIM  62. Atlassian Confluence — SCIM  63. Bitbucket — SCIM
64. GitHub Enterprise — SCIM/Claim  65. GitLab — SCIM/Claim  66. Box — SCIM
67. Dropbox Business — SCIM  68. Google Workspace — SCIM  69. AWS IAM Identity Center — SCIM/Claim
70. Okta — SCIM  71. Adobe Creative Cloud — SCIM  72. Adobe Document Cloud — SCIM
73. Zscaler ZIA — SCIM/Claim  74. Zscaler ZPA — SCIM/Claim  75. Cisco Duo — Claim
76. Cisco Umbrella — SCIM  77. CrowdStrike Falcon — AppRole  78. Snowflake — SCIM/Claim
79. Databricks — SCIM  80. Tableau — SCIM  81. Zendesk — SCIM  82. Freshservice — SCIM
83. DocuSign — AppRole  84. Smartsheet — SCIM  85. Asana — SCIM  86. monday.com — SCIM
87. Notion — SCIM  88. Miro — SCIM  89. Figma — SCIM  90. Lucid (Lucidchart) — SCIM
91. Workplace from Meta — SCIM  92. Cornerstone OnDemand — SCIM  93. Pluralsight — SCIM
94. LinkedIn Learning — SCIM  95. Udemy Business — SCIM  96. Citrix Cloud — Claim
97. VMware Workspace ONE — SCIM  98. Jamf Pro — SCIM/Claim  99. Mimecast — SCIM
100. Proofpoint — SCIM  101. PagerDuty — SCIM  102. Opsgenie — SCIM  103. Datadog — SCIM/Claim
104. Splunk — SCIM/Claim  105. Grafana — Claim  106. New Relic — SCIM  107. 1Password — SCIM
108. CyberArk — SCIM/Claim  109. SailPoint — SCIM  110. Saviynt — SCIM
111. HashiCorp Vault / Terraform Cloud — Claim  112. Snyk — Claim  113. ServiceTitan — AppRole
114. NetSuite — SAML/AppRole  115. HubSpot — AppRole  116. Marketo — AppRole
117. Qualtrics — SCIM  118. Airtable — SCIM  119. ClickUp — SCIM  120. Calendly — SCIM

---

## What PIM4EntraPS does per mechanism
- **RBAC-API (✅/◑)** — a workload connector lists the app's roles and assigns the PIM group to a role, idempotently (`Apply-PimWorkloadAssignments`). Built: Intune, Defender XDR. Eligible-but-need-an-auth-adapter: Azure RBAC (ARM), Power BI, Dataverse/Dynamics, Business Central, Azure DevOps, Exchange Online. Graph-native ones (Entra directory roles, Purview, MDCA, Defender for *) drop in as new `*.connector.json` with the existing Graph adapter.
- **AppRole (○)** — one generic pattern: assign the PIM/Entra group to the enterprise app's app role via Graph `servicePrincipals/{id}/appRoleAssignedTo`. A single `entra-approle` connector covers every gallery app.
- **SCIM (○)** — assignment = add the group to the enterprise app's *Users and groups*; Entra's provisioning job pushes it. No per-app connector; governed by the provisioning configuration.
- **Claim / License (○)** — assignment = group membership; the app reads the token claim or the license follows the group. No connector needed.

So "100+ apps" reduce to **a handful of connector patterns**: the per-workload RBAC connectors (build as needed) + one generic `entra-approle` connector + standard SCIM/claim/licensing (no code). That keeps the surface small while covering the whole estate.

## Build order for connectors (by demand)
1. **entra-roles** (Graph, existing adapter) — Entra directory roles to role-assignable groups.
2. **entra-approle** (Graph, existing adapter) — generic enterprise-app app-role assignment (covers most gallery apps).
3. **azure-rbac** — needs an ARM auth adapter (the most-requested after Intune/Defender).
4. **powerbi** — needs the Power BI auth adapter.
5. **exchange-online**, **dataverse/dynamics**, **business-central**, **azure-devops** — per-workload auth adapters; build on customer demand.
