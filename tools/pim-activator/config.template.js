// Copy to config.js and fill in. config.js is gitignored.
// See README.md for app-registration setup.
window.PIM_CONFIG = {
  // Your Entra tenant id (GUID).
  tenantId: "00000000-0000-0000-0000-000000000000",

  // Client (application) id of the SPA app registration that holds the
  // delegated PrivilegedAccess.ReadWrite.AzureADGroup + Group.Read.All perms.
  clientId: "00000000-0000-0000-0000-000000000000",

  // Optional naming-convention filter. If set, only groups whose displayName
  // matches this regex are shown. Default: show all eligible groups.
  groupNameFilter: "^PIM-",

  // Default activation duration in hours (max set by tenant policy, typically 8).
  defaultDurationHours: 8,

  // Default text for the justification field. User can edit before activate.
  defaultJustification: "Daily ops"
};
