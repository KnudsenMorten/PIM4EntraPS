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

-- schema upgrade for pre-existing installs (idempotent)
IF COL_LENGTH('pim.CentralAdmins', 'FirstName') IS NULL
    ALTER TABLE pim.CentralAdmins ADD FirstName NVARCHAR(100) NULL, LastName NVARCHAR(100) NULL, Initials NVARCHAR(10) NULL, UsageLocation CHAR(2) NULL;
IF COL_LENGTH('pim.CentralAdmins', 'Purpose') IS NULL
    ALTER TABLE pim.CentralAdmins ADD Purpose NVARCHAR(20) NULL;
IF COL_LENGTH('pim.CentralAdmins', 'TierLevel') IS NOT NULL
    ALTER TABLE pim.CentralAdmins DROP COLUMN TierLevel;

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
-- Same semantics as the engine: an admin reaches a tenant when
-- admin.Ring <= tenant.Ring is FALSE -- careful: ring 0 = broadest reach.
-- Engine rule today: admin row deploys when admin.Ring <= tenant ring? No:
-- Select-PimAdminRowsByRing keeps rows where admin.Ring <= PIM_TenantRing,
-- i.e. a RING-0 admin (Ring=0) deploys EVERYWHERE (0 <= every tenant ring),
-- a ring-2 admin only reaches tenants whose ring is >= 2 (test tenants).
IF OBJECT_ID('pim.vw_AdminTenantTargets') IS NOT NULL DROP VIEW pim.vw_AdminTenantTargets;
GO
CREATE VIEW pim.vw_AdminTenantTargets AS
SELECT a.UserName, a.Upn, a.Ring AS AdminRing, t.TenantId, t.DisplayName AS TenantName, t.Ring AS TenantRing
FROM pim.CentralAdmins a
JOIN platform.Tenants t ON a.Ring <= t.Ring
WHERE a.Enabled = 1 AND t.Enabled = 1;
GO
