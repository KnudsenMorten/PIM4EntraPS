# emergency.custom.sample.ps1 -- copy to emergency.custom.ps1 (gitignored) to
# arm the Manager's break-glass override (LIFECYCLE-GOVERNANCE phase 8).
#
# The Manager verifies the operator-entered passphrase against this SHA256
# hash (constant-time compare; 5 failures lock the endpoint for 15 minutes).
# Generate the hash for your chosen passphrase:
#
#   [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash(
#       [Text.Encoding]::UTF8.GetBytes('YOUR-PASSPHRASE-HERE'))).Replace('-','').ToLower()
#
# Store the passphrase itself in your password vault -- only the hash lives
# on disk.
#
# PREFERRED: Key-Vault-backed passcode (so the break-glass works from any client
# PC against the central secret). Set the vault name below; the secret named
# PIM-EmergencyPasscode may hold either the passphrase (it gets hashed) or a
# 64-char SHA256 hex. KV wins; the local hash is the fallback.
#
#   $global:PIM_EmergencyVault          = 'kv-yourcustomer'
#   $global:PIM_EmergencyPasscodeSecret = 'PIM-EmergencyPasscode'   # (this is the default)

$global:PIM_EmergencyPasscodeHash = '<paste the sha256 hex here>'
