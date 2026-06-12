-- platform-seed-demo.sql -- FICTIONAL MSP simulation data (5 tenants, 3 central admins).
-- Mirrors the TenantManager -Demo ring topology. Idempotent (MERGE-by-key).

MERGE platform.Tenants AS t
USING (VALUES
    ('11111111-1111-1111-1111-111111111101', N'Demo Ring2 Lab A',     2, N'test tenant -- first to receive changes'),
    ('11111111-1111-1111-1111-111111111102', N'Demo Ring2 Lab B',     2, N'test tenant'),
    ('11111111-1111-1111-1111-111111111103', N'Demo Ring1 Pilot',     1, N'pilot customer'),
    ('11111111-1111-1111-1111-111111111104', N'Demo Ring0 Prod East', 0, N'broad production'),
    ('11111111-1111-1111-1111-111111111105', N'Demo Ring0 Prod West', 0, N'broad production')
) AS s (TenantId, DisplayName, Ring, Notes)
ON t.TenantId = s.TenantId
WHEN NOT MATCHED THEN INSERT (TenantId, DisplayName, Ring, Notes) VALUES (s.TenantId, s.DisplayName, s.Ring, s.Notes)
WHEN MATCHED THEN UPDATE SET DisplayName = s.DisplayName, Ring = s.Ring, Notes = s.Notes, UpdatedAtUtc = SYSUTCDATETIME();

MERGE platform.TenantApps AS t
USING (VALUES
    ('11111111-1111-1111-1111-111111111101', N'PIM', '22222222-2222-2222-2222-222222222201', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA01'),
    ('11111111-1111-1111-1111-111111111103', N'PIM', '22222222-2222-2222-2222-222222222203', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA03'),
    ('11111111-1111-1111-1111-111111111104', N'PIM', '22222222-2222-2222-2222-222222222204', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA04')
) AS s (TenantId, Product, AppId, CertificateThumbprint)
ON t.TenantId = s.TenantId AND t.Product = s.Product
WHEN NOT MATCHED THEN INSERT (TenantId, Product, AppId, CertificateThumbprint) VALUES (s.TenantId, s.Product, s.AppId, s.CertificateThumbprint)
WHEN MATCHED THEN UPDATE SET AppId = s.AppId, CertificateThumbprint = s.CertificateThumbprint, UpdatedAtUtc = SYSUTCDATETIME();

MERGE pim.CentralAdmins AS t
USING (VALUES
    (N'Admin-AAA-L0-T0-ID', N'Demo Admin Ring0 (broad)',  N'admin-aaa-l0-t0-id@demo-mgmt.example', 0, NULL),
    (N'Admin-BBB-L1-T1-ID', N'Demo Admin Ring1 (pilot)',  N'admin-bbb-l1-t1-id@demo-mgmt.example', 1, NULL),
    (N'Admin-CCC-L3-T1-ID', N'Demo Consultant Ring2',     N'admin-ccc-l3-t1-id@demo-mgmt.example', 2, N'consultant')
) AS s (UserName, DisplayName, Upn, Ring, Template)
ON t.UserName = s.UserName
WHEN NOT MATCHED THEN INSERT (UserName, DisplayName, Upn, Ring, Template) VALUES (s.UserName, s.DisplayName, s.Upn, s.Ring, s.Template)
WHEN MATCHED THEN UPDATE SET DisplayName = s.DisplayName, Upn = s.Upn, Ring = s.Ring, Template = s.Template, UpdatedAtUtc = SYSUTCDATETIME();

-- Secret pointers (no secret values in demo data)
MERGE platform.Secrets AS t
USING (VALUES
    (N'Smtp-Password',    N'KeyVault', N'https://kv-demo.vault.azure.net/secrets/smtp-password')
) AS s (Name, Store, KeyVaultUri)
ON t.Name = s.Name
WHEN NOT MATCHED THEN INSERT (Name, Store, KeyVaultUri) VALUES (s.Name, s.Store, s.KeyVaultUri);
