# PIM4EntraPS local-plane engine -- cloud-native container (no local VM).
# LIFECYCLE-GOVERNANCE § 19 / MSP-ARCHITECTURE.md § 11a.
#
# The entrypoint is REST-based (no Graph SDK / SqlServer module) so the image is
# small and free of the Azure.Core assembly conflict. Run it as an ACI or
# Container Apps Job INSIDE the customer VNet, on a schedule.
FROM mcr.microsoft.com/powershell:latest

WORKDIR /pim
COPY engine/_shared/PIM-Baseline.ps1      /pim/engine/_shared/PIM-Baseline.ps1
COPY engine/container/Start-PimEngineContainer.ps1 /pim/Start-PimEngineContainer.ps1

# Non-root
USER 1000
ENTRYPOINT ["pwsh","-NoProfile","-File","/pim/Start-PimEngineContainer.ps1"]
