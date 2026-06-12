-- local-schema.sql -- per-tenant LOCAL store (LIFECYCLE-GOVERNANCE § 19).
--
-- Lives in the CUSTOMER's own Azure (their subscription, their private
-- endpoint, their Conditional Access, their backup). Holds ONLY the
-- Owner=Local config the customer's local IT manages: their own day-2-day
-- admins and their local Azure resource scopes.
--
-- The MSP never connects here. The engine -- running with the per-tenant
-- credential, reaching outward -- reads this store and MERGES it with the
-- signed MSP baseline bundle it pulled + verified. The two stores are never
-- linked; only signed artifacts cross the boundary.
--
-- Separation, NOT gatekeeping: local IT manages their tenant autonomously --
-- including privileged accounts -- with no MSP request or approval. The MSP
-- baseline is pulled down and merged additively at engine runtime. The Owner
-- tag is provenance only (Owner=MSP rows are refreshed on each baseline pull,
-- so they aren't hand-edited locally); it does NOT gate what local may create.

IF SCHEMA_ID('pim') IS NULL EXEC ('CREATE SCHEMA pim');

IF OBJECT_ID('pim.LocalAdmins') IS NULL
CREATE TABLE pim.LocalAdmins (
    UserName      NVARCHAR(100) NOT NULL PRIMARY KEY,   -- Admin-<INI>-ID (day-2-day convention)
    DisplayName   NVARCHAR(200) NOT NULL,
    FirstName     NVARCHAR(100) NULL,
    LastName      NVARCHAR(100) NULL,
    Initials      NVARCHAR(10)  NULL,
    UsageLocation CHAR(2)       NULL,
    Purpose       NVARCHAR(20)  NOT NULL CONSTRAINT DF_LocalAdmins_Purpose DEFAULT 'Day2Day',
    Owner         NVARCHAR(10)  NOT NULL CONSTRAINT DF_LocalAdmins_Owner DEFAULT 'Local',
    Enabled       BIT           NOT NULL CONSTRAINT DF_LocalAdmins_Enabled DEFAULT 1,
    Notes         NVARCHAR(1000) NULL,
    UpdatedAtUtc  DATETIME2     NOT NULL CONSTRAINT DF_LocalAdmins_Updated DEFAULT SYSUTCDATETIME(),
    -- Provenance only: rows in the local store are Local-owned. Local IT may
    -- create ANY Purpose (incl. HighPriv) -- the MSP is not an approval gate.
    CONSTRAINT CK_LocalAdmins_OwnerLocal CHECK (Owner = 'Local')
);
-- Idempotent: drop the legacy gatekeeping guardrail if a prior deploy created it.
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_LocalAdmins_NoHighPriv' AND parent_object_id = OBJECT_ID('pim.LocalAdmins'))
    ALTER TABLE pim.LocalAdmins DROP CONSTRAINT CK_LocalAdmins_NoHighPriv;

-- Local Azure resource scopes the customer's local IT may manage. The allowed
-- scope is bounded by the MSP baseline (a prefix under the customer's own
-- management group); rows outside that prefix are rejected by the engine at
-- apply time against the pulled baseline.
IF OBJECT_ID('pim.LocalResources') IS NULL
CREATE TABLE pim.LocalResources (
    Id            INT IDENTITY(1,1) PRIMARY KEY,
    GroupTag      NVARCHAR(200) NOT NULL,
    AzScope       NVARCHAR(400) NOT NULL,   -- /subscriptions/... under the local MG
    RoleName      NVARCHAR(200) NOT NULL,   -- Azure RBAC role
    Owner         NVARCHAR(10)  NOT NULL CONSTRAINT DF_LocalRes_Owner DEFAULT 'Local',
    Notes         NVARCHAR(1000) NULL,
    UpdatedAtUtc  DATETIME2     NOT NULL CONSTRAINT DF_LocalRes_Updated DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_LocalRes_OwnerLocal CHECK (Owner = 'Local')
);

-- The local IT's view of "everything that applies to my tenant" is produced at
-- ENGINE RUNTIME by merging this store with the pulled MSP baseline -- it is
-- intentionally NOT a SQL view here, because the MSP rows live in a different
-- store that this database is never linked to.
