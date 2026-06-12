-- local-seed-demo.sql -- FICTIONAL local-IT data for one customer tenant.
-- Represents what the customer's OWN local IT created and manages in their
-- local store: day-2-day admins (Admin-<INI>-ID) + a local Azure scope under
-- their management group. Idempotent (MERGE-by-key).

MERGE pim.LocalAdmins AS t
USING (VALUES
    (N'Admin-HELP-ID', N'Local Helpdesk (Cloud, ID)', N'Local', N'Helpdesk', N'HELP', 'DK', N'Day2Day', N'created by local IT -- tenant-owned'),
    (N'Admin-OPS-ID',  N'Local Operations (Cloud, ID)', N'Local', N'Operations', N'OPS', 'DK', N'Day2Day', N'created by local IT -- tenant-owned')
) AS s (UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Notes)
ON t.UserName = s.UserName
WHEN NOT MATCHED THEN INSERT (UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Notes)
    VALUES (s.UserName, s.DisplayName, s.FirstName, s.LastName, s.Initials, s.UsageLocation, s.Purpose, s.Notes)
WHEN MATCHED THEN UPDATE SET DisplayName = s.DisplayName, FirstName = s.FirstName, LastName = s.LastName,
    Initials = s.Initials, UsageLocation = s.UsageLocation, Purpose = s.Purpose, Notes = s.Notes, UpdatedAtUtc = SYSUTCDATETIME();

MERGE pim.LocalResources AS t
USING (VALUES
    (N'ROLE-Local-VMOperators', N'/subscriptions/00000000-0000-0000-0000-0000000000aa', N'Virtual Machine Contributor', N'local workload under the customer MG')
) AS s (GroupTag, AzScope, RoleName, Notes)
ON t.GroupTag = s.GroupTag AND t.AzScope = s.AzScope
WHEN NOT MATCHED THEN INSERT (GroupTag, AzScope, RoleName, Notes) VALUES (s.GroupTag, s.AzScope, s.RoleName, s.Notes);
