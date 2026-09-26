-- platform-schema.sql -- common MSP platform registry (LIFECYCLE-GOVERNANCE § 16 / phase 12)
-- Shared by PIM4EntraPS and TenantManager. Identical on Azure SQL and
-- on-prem/hybrid SQL Server. Idempotent (IF NOT EXISTS guards).
--
-- Security model:
--   * AppId + CertificateThumbprint are IDENTIFIERS, not secrets -> plain columns.
--   * Private keys live in the Windows machine certificate store (non-exportable)
--     on enrolled boxes -- never in this database.
--   * platform.Secrets holds only the residual secrets (SMTP password, intake
--     HMAC key, ...) and is designed for Always Encrypted: enroll a column
--     master key certificate per trusted machine and encrypt CipherValue.
--     Store='KeyVault' rows hold no value here -- only the KeyVaultUri pointer.

IF SCHEMA_ID('platform') IS NULL EXEC ('CREATE SCHEMA platform');
IF SCHEMA_ID('pim') IS NULL EXEC ('CREATE SCHEMA pim');

IF OBJECT_ID('platform.Tenants') IS NULL
CREATE TABLE platform.Tenants (
    TenantId        UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    DisplayName     NVARCHAR(200)    NOT NULL,
    Ring            TINYINT          NOT NULL CONSTRAINT DF_Tenants_Ring DEFAULT 2,  -- 2=test, 1=pilot, 0=broad
    Enabled         BIT              NOT NULL CONSTRAINT DF_Tenants_Enabled DEFAULT 1,
    Notes           NVARCHAR(1000)   NULL,
    CreatedAtUtc    DATETIME2        NOT NULL CONSTRAINT DF_Tenants_Created DEFAULT SYSUTCDATETIME(),
    UpdatedAtUtc    DATETIME2        NOT NULL CONSTRAINT DF_Tenants_Updated DEFAULT SYSUTCDATETIME()
);

IF OBJECT_ID('platform.TenantApps') IS NULL
CREATE TABLE platform.TenantApps (
    TenantId              UNIQUEIDENTIFIER NOT NULL REFERENCES platform.Tenants(TenantId),
    Product               NVARCHAR(40)     NOT NULL,   -- 'PIM' | 'TenantManager' | ...
    AppId                 UNIQUEIDENTIFIER NOT NULL,
    CertificateThumbprint CHAR(40)         NULL,        -- identifier; private key stays in the machine cert store
    AuthMode              NVARCHAR(30)     NOT NULL CONSTRAINT DF_TenantApps_Auth DEFAULT 'Certificate',  -- Certificate | SecretRef
    SecretName            NVARCHAR(200)    NULL,        -- -> platform.Secrets when AuthMode=SecretRef
    UpdatedAtUtc          DATETIME2        NOT NULL CONSTRAINT DF_TenantApps_Updated DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_TenantApps PRIMARY KEY (TenantId, Product)
);

IF OBJECT_ID('platform.Secrets') IS NULL
CREATE TABLE platform.Secrets (
    Name          NVARCHAR(200)  NOT NULL PRIMARY KEY,
    Store         NVARCHAR(30)   NOT NULL,              -- 'KeyVault' | 'SqlAlwaysEncrypted'
    KeyVaultUri   NVARCHAR(400)  NULL,                  -- Store=KeyVault: pointer only, no value here
    CipherValue   VARBINARY(MAX) NULL,                  -- Store=SqlAlwaysEncrypted: AE-encrypted client-side
    UpdatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_Secrets_Updated DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_Secrets_Shape CHECK (
        (Store = 'KeyVault' AND KeyVaultUri IS NOT NULL AND CipherValue IS NULL) OR
        (Store = 'SqlAlwaysEncrypted' AND KeyVaultUri IS NULL)
    )
);

IF OBJECT_ID('pim.CentralAdmins') IS NULL
CREATE TABLE pim.CentralAdmins (
    UserName     NVARCHAR(100) NOT NULL PRIMARY KEY,    -- naming-convention login (carries L0/T0 markers)
    DisplayName  NVARCHAR(200) NOT NULL,
    Upn          NVARCHAR(320) NOT NULL,
    Ring         TINYINT       NOT NULL CONSTRAINT DF_CentralAdmins_Ring DEFAULT 2,
    Template     NVARCHAR(100) NULL,                    -- admin template id (consultant / new-employee-next-month / ...)
    Enabled      BIT           NOT NULL CONSTRAINT DF_CentralAdmins_Enabled DEFAULT 1,
    Notes        NVARCHAR(1000) NULL,
    UpdatedAtUtc DATETIME2     NOT NULL CONSTRAINT DF_CentralAdmins_Updated DEFAULT SYSUTCDATETIME(),
    -- account-material fields consumed by the MSP fan-out (per-tenant account
    -- creation; UPN per tenant = UserName@<tenant default domain>)
    FirstName     NVARCHAR(100) NULL,
    LastName      NVARCHAR(100) NULL,
    Initials      NVARCHAR(10)  NULL,
    UsageLocation CHAR(2)       NULL,
    -- Day2Day (Admin-INI-PLAT, no markers) | HighPriv (Admin-INI-L0-T0-PLAT).
    -- Replaced the misleading TierLevel column (v2.4.171): a day-2-day account
    -- spans multiple tier assignments, so a per-account tier was meaningless.
    Purpose       NVARCHAR(20)  NULL
);

-- MSP-4 (BUG-62): the tenant's TAGS -- the currency artifact targeting is expressed in
-- ("this role goes to only 5 of the 28"). A semicolon/comma separated list, e.g.
-- 'retail;vip'. The downlink never reads this table: a managed tenant has no credential
-- for the master's registry, so the per-tenant tag map is carried IN the signed bundle
-- (the cloud publish job, PIM-BaselinePublish -> payload.tenantTags), exactly as the projection policy is and
-- for the same reason. Signed, so a tenant cannot quietly re-tag itself into scope.
-- Absent/empty = untagged = matches only '*' targets, which is today's behaviour.
IF COL_LENGTH('platform.Tenants', 'Tags') IS NULL
    ALTER TABLE platform.Tenants ADD Tags NVARCHAR(400) NULL;

-- schema upgrade for pre-existing installs (idempotent)
IF COL_LENGTH('pim.CentralAdmins', 'FirstName') IS NULL
    ALTER TABLE pim.CentralAdmins ADD FirstName NVARCHAR(100) NULL, LastName NVARCHAR(100) NULL, Initials NVARCHAR(10) NULL, UsageLocation CHAR(2) NULL;
IF COL_LENGTH('pim.CentralAdmins', 'Purpose') IS NULL
    ALTER TABLE pim.CentralAdmins ADD Purpose NVARCHAR(20) NULL;
IF COL_LENGTH('pim.CentralAdmins', 'TierLevel') IS NOT NULL
    ALTER TABLE pim.CentralAdmins DROP COLUMN TierLevel;
-- § 19 Owner tag: rows in the central registry are MSP-owned baseline by
-- definition (the local store holds Owner=Local). Kept explicit so a merged
-- view across both stores can attribute every row.
IF COL_LENGTH('pim.CentralAdmins', 'Owner') IS NULL
    ALTER TABLE pim.CentralAdmins ADD Owner NVARCHAR(10) NOT NULL CONSTRAINT DF_CentralAdmins_Owner DEFAULT 'MSP';

-- 🔑 OPERATOR DECISION 2026-08-13 -- A SYNCED MSP ADMIN MUST BE ABLE TO SIGN IN.
-- Both apply paths used to HARDCODE CreateTAP='FALSE' for every downlinked/fanned-out admin,
-- on the reasoning that a sync must not silently mint a credential in a customer tenant. The
-- measured consequence was the opposite of safe: the accounts landed in the managed tenant
-- with no credential and no way to obtain one, so the MSP could not actually administer the
-- customer it had just been granted access to -- an account that cannot sign in is not a
-- delivered account. TAP issuance is therefore ON by default and expressed HERE, per admin,
-- so it stays the MSP's declared intent rather than a constant buried in two code paths.
--   CreateTap        1 = the managed tenant's own engine mints a TAP for this admin (default ON)
--   TapLifetimeHours NULL = fall back to the downlink default (8h); the engine floors at 4h
--   ManagerEmail     LEGACY FALLBACK ONLY (DOC-17 g). Since 71.19 a TAP is delivered to the owners of
--                    the admin's SPONSOR DEPARTMENT (the admin's Department -> that department's
--                    Owners in PIM-Definitions-Departments, 62), not to this column. It is read only
--                    when the admin names no sponsor department. With neither, the engine REFUSES to
--                    mint a TAP it cannot deliver -- so set the admin's Department and give that
--                    department Owners; CreateTap alone does not produce a usable admin.
IF COL_LENGTH('pim.CentralAdmins', 'CreateTap') IS NULL
    ALTER TABLE pim.CentralAdmins ADD
        CreateTap        BIT           NOT NULL CONSTRAINT DF_CentralAdmins_CreateTap DEFAULT 1,
        TapLifetimeHours INT           NULL,
        ManagerEmail     NVARCHAR(320) NULL;

-- MSP-4 (BUG-62): WHICH TENANTS this admin reaches, on top of the ring. Selector syntax is
-- Test-PimArtifactTarget's: absent or '*' = every managed tenant (so existing rows are
-- unaffected), a bare word or 'tag:x' = tenants carrying that tag, 'tenant:<guid>' = one
-- named tenant, a ';'/',' list matches on ANY -- and 'none' means MSP-local, never published,
-- which wins over anything beside it.
IF COL_LENGTH('pim.CentralAdmins', 'Target') IS NULL
    ALTER TABLE pim.CentralAdmins ADD Target NVARCHAR(400) NULL;

-- §71 / framework MSP-4 SURFACE (the replication target contract): Replicate = No | Yes | Follow.
-- NULL = the documented default, which for a registry row is Yes (the registry holds MSP admins by
-- construction) -- so every existing row keeps publishing exactly as before. 'No' keeps an admin in
-- the registry but out of the signed bundle (the cloud publish job, PIM-BaselinePublish / Select-PimBaselineBundleContent).
-- Additive only.
IF COL_LENGTH('pim.CentralAdmins', 'Replicate') IS NULL
    ALTER TABLE pim.CentralAdmins ADD Replicate NVARCHAR(10) NULL;

-- MSP-2 / control #2: PER-RELATIONSHIP role projection policy.
--
-- The downlink reflects a master admin's PIM-group memberships into the managed
-- tenant, so a synced admin gets their roles through the SAME path a local admin
-- does (group membership -> PIM-Assignments-Admins -> the engine's AdminMembers
-- provider). WHICH of those memberships project is a property of the RELATIONSHIP,
-- not of the admin -- an MSP does not give every customer the same delegation.
--
-- The baseline bundle is ONE fleet-wide signed artifact, so it cannot carry a
-- per-tenant filter; the master publishes what each MSP admin holds and the filter
-- is applied per tenant at downlink time from this table. That keeps the courier
-- model (one signed bundle, verified by every tenant) intact.
--
-- SEMANTICS (Select-PimProjectedAssignments is the single implementation):
--   * no rows for a tenant  -> ALLOW ALL (operator decision 2026-08-12). A new
--     relationship reflects the master's delegation by default; the plan always
--     reports what projected and what was excluded, so this is never silent.
--   * any Mode='allow' row  -> ALLOW-LIST: only matching tags project.
--   * Mode='deny' rows      -> always subtract, and win over an allow match.
--   * GroupTag supports a trailing * wildcard ('ROLE-*'); matching is case-insensitive.
IF OBJECT_ID('pim.TenantRoleProjection') IS NULL
CREATE TABLE pim.TenantRoleProjection (
    TenantId     UNIQUEIDENTIFIER NOT NULL REFERENCES platform.Tenants(TenantId),
    Mode         NVARCHAR(10)     NOT NULL,   -- 'allow' | 'deny'
    GroupTag     NVARCHAR(200)    NOT NULL,   -- exact tag, or a trailing-* prefix
    Notes        NVARCHAR(1000)   NULL,
    UpdatedAtUtc DATETIME2        NOT NULL CONSTRAINT DF_TenantRoleProj_Updated DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_TenantRoleProjection PRIMARY KEY (TenantId, Mode, GroupTag),
    CONSTRAINT CK_TenantRoleProjection_Mode CHECK (Mode IN ('allow','deny'))
);

-- 🔴 DELIBERATELY NOT HERE: a managed tenant's store server/database.
-- Added briefly on 2026-08-13 so the Manager could write into a customer's store, then
-- REMOVED the same day when that whole direction was replaced. Under the agreed model
-- (framework MSP-3) the managed tenant PULLS and applies with its OWN identity, so the
-- master has no business holding a customer's store coordinates -- and §22 says customer
-- data never leaves their tenant. If a future uplink genuinely needs a pointer, it is an
-- uplink concern, not a column the master reads to reach in.

IF OBJECT_ID('platform.AuditEvents') IS NULL
CREATE TABLE platform.AuditEvents (
    Id            BIGINT IDENTITY(1,1) PRIMARY KEY,
    Ts            DATETIME2     NOT NULL CONSTRAINT DF_Audit_Ts DEFAULT SYSUTCDATETIME(),
    RunId         NVARCHAR(64)  NULL,
    CorrelationId NVARCHAR(64)  NULL,
    Actor         NVARCHAR(200) NOT NULL,
    Action        NVARCHAR(100) NOT NULL,
    Target        NVARCHAR(400) NOT NULL,
    BeforeJson    NVARCHAR(MAX) NULL,
    AfterJson     NVARCHAR(MAX) NULL,
    Result        NVARCHAR(100) NOT NULL CONSTRAINT DF_Audit_Result DEFAULT 'ok',
    WhatIf        BIT           NOT NULL CONSTRAINT DF_Audit_WhatIf DEFAULT 0
);

-- MSP ring fan-out: which central admin deploys to which tenant.
-- DOC-17 p + §77.20 (2.4.388): ONE rule, the engine's (Test-PimRingReaches: tenant ring <= admin ring), and this
-- view's JOIN is the same comparison: t.Ring <= a.Ring. Ring 0 = dev, 1 = test, 2 = broad (the update-ring order):
--   * a ring-0 admin (a new hire) reaches only ring-0 (dev) tenants;
--   * a ring-2 admin reaches EVERY tenant (every tenant ring <= 2).
--
-- 🔴 §71.7 (d): THIS VIEW USED TO IGNORE Target AND Tags, so it OVERSTATED reach -- an admin targeted at
-- 'tag:vip' was listed against every tenant its ring admitted, and the MSP fan-out (S5) reads exactly
-- this view. It now applies the contract rule: ring AND target AND tags (framework MSP-4 SURFACE item 4):
--   * Replicate='No' or a 'none' term       -> no tenant
--   * Target blank / '*' / 'all'            -> every tenant the ring admits (unchanged for existing rows)
--   * 'tenant:<id>'                         -> that tenant
--   * 'tag:<key:value>' or a bare tag       -> tenants carrying it (terms are ANY-of)
--   * 'tag:a+b'                             -> tenants carrying BOTH (ALL-of)
-- The same grammar Test-PimArtifactTarget evaluates in the downlink, so the registry view and the
-- signed-bundle plan cannot disagree about who reaches whom.
-- STRING_SPLIT needs database compatibility level 130+ (Azure SQL / SQL Server 2016+). On an older
-- level the view falls back to ring + Replicate + 'none' only -- narrower than before, never wider --
-- rather than failing the whole schema apply and leaving no view at all.
IF OBJECT_ID('pim.vw_AdminTenantTargets') IS NOT NULL DROP VIEW pim.vw_AdminTenantTargets;
GO
IF (SELECT compatibility_level FROM sys.databases WHERE database_id = DB_ID()) >= 130
EXEC('CREATE VIEW pim.vw_AdminTenantTargets AS
SELECT a.UserName, a.Upn, a.Ring AS AdminRing, t.TenantId, t.DisplayName AS TenantName, t.Ring AS TenantRing
FROM pim.CentralAdmins a
JOIN platform.Tenants t ON t.Ring <= a.Ring
WHERE a.Enabled = 1 AND t.Enabled = 1
  AND ISNULL(LTRIM(RTRIM(a.Replicate)), '''') <> ''No''
  AND NOT EXISTS (SELECT 1 FROM STRING_SPLIT(REPLACE(ISNULL(a.Target, ''''), '';'', '',''), '','') n
                  WHERE LTRIM(RTRIM(n.value)) = ''none'')
  AND ( LTRIM(RTRIM(ISNULL(a.Target, ''''))) = ''''
        OR EXISTS (
            SELECT 1 FROM STRING_SPLIT(REPLACE(a.Target, '';'', '',''), '','') term
            WHERE LTRIM(RTRIM(term.value)) IN (''*'', ''all'')
               OR LTRIM(RTRIM(term.value)) = ''tenant:'' + CONVERT(nvarchar(50), t.TenantId)
               OR ( LTRIM(RTRIM(term.value)) <> ''''
                    AND LTRIM(RTRIM(term.value)) NOT LIKE ''tenant:%''
                    AND LTRIM(RTRIM(term.value)) NOT IN (''*'', ''all'', ''none'')
                    AND NOT EXISTS (
                        SELECT 1 FROM STRING_SPLIT(CASE WHEN LTRIM(RTRIM(term.value)) LIKE ''tag:%''
                                                        THEN SUBSTRING(LTRIM(RTRIM(term.value)), 5, 400)
                                                        ELSE LTRIM(RTRIM(term.value)) END, ''+'') part
                        WHERE NOT EXISTS (
                            SELECT 1 FROM STRING_SPLIT(REPLACE(ISNULL(t.Tags, ''''), '';'', '',''), '','') tt
                            WHERE LTRIM(RTRIM(tt.value)) <> '''' AND LTRIM(RTRIM(tt.value)) = LTRIM(RTRIM(part.value))))))
      )')
ELSE
EXEC('CREATE VIEW pim.vw_AdminTenantTargets AS
SELECT a.UserName, a.Upn, a.Ring AS AdminRing, t.TenantId, t.DisplayName AS TenantName, t.Ring AS TenantRing
FROM pim.CentralAdmins a
JOIN platform.Tenants t ON t.Ring <= a.Ring
WHERE a.Enabled = 1 AND t.Enabled = 1
  AND ISNULL(LTRIM(RTRIM(a.Replicate)), '''') <> ''No''
  AND '','' + REPLACE(REPLACE(ISNULL(a.Target, ''''), '' '', ''''), '';'', '','') + '','' NOT LIKE ''%,none,%''
  AND LTRIM(RTRIM(ISNULL(a.Target, ''''))) IN ('''', ''*'', ''all'')');
GO
