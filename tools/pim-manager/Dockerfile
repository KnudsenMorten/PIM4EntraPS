# PIM Manager -- 24/7 hosted (App Service for Containers / Container Apps).
# Runs the Manager in HOSTED mode: binds the container port, never self-exits,
# trusts the App Service Easy Auth principal header for identity.
#
# Build context = repo root:
#   docker build -f SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile -t <acr>/pim-manager:<tag> .
#
# NOTE: the SQL data layer uses System.Data.SqlClient. On Linux/.NET that package
# must be present; if your image can't load it, switch the base to a Windows
# container (System.Data.SqlClient ships in-box on Windows PowerShell) OR port
# New-PimSqlConnection to Microsoft.Data.SqlClient. Graph modules are needed for
# the live Revoke/refresh endpoints.

FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

# Microsoft.Data.SqlClient (Linux-safe SQL) + the Graph modules the live endpoints use.
RUN pwsh -NoProfile -Command "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force -ErrorAction SilentlyContinue; \
    Install-Module Az.Accounts -Scope AllUsers -Force -ErrorAction SilentlyContinue"

WORKDIR /app
COPY SOLUTIONS/PIM4EntraPS /app/PIM4EntraPS

# Hosted defaults; the platform injects PORT/WEBSITES_PORT + the SQL connection.
ENV PIM_HOSTED=1
ENV PORT=8080
EXPOSE 8080

# StorageBackend=sql + the Azure SQL connection are supplied via app settings /
# Managed Identity at runtime (no secret baked into the image).
ENTRYPOINT ["pwsh","-NoProfile","-ExecutionPolicy","Bypass","-File","/app/PIM4EntraPS/tools/pim-manager/Open-PimManager.ps1","-Server","-Hosted","-NoLaunch"]
