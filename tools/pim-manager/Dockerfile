# PIM Manager -- 24/7 hosted (App Service for Containers / Container Apps).
# Runs the Manager in HOSTED mode: binds the container port, never self-exits,
# trusts the App Service Easy Auth principal header for identity.
#
# Build context = repo root:
#   docker build -f SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile -t <acr>/pim-manager:<tag> .
#
# REST-only: NO PowerShell modules at all (Graph/ARM/Power BI go over REST via
# PIM-Rest.ps1). The SQL data plane has no REST API, so a TDS driver is unavoidable --
# but it's a pinned .NET ASSEMBLY, NOT a PowerShell module. Stage 1 uses the .NET SDK to
# fetch a pinned Microsoft.Data.SqlClient + its dependency closure; stage 2 copies the
# DLLs into the runtime image and PIM-SqlStore Add-Types them ($env:PIM_SQLCLIENT_DLL).
# No Install-Module, no gallery, no auto-update -- the version is frozen in the image.

# ---- stage 1: fetch the pinned SQL driver assembly (no PS module) ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS sqldriver
WORKDIR /drv
RUN dotnet new classlib -n shim -o shim \
 && cd shim \
 && dotnet add package Microsoft.Data.SqlClient --version 5.2.2 \
 && dotnet publish -c Release -o /drv/out

# ---- stage 2: runtime ----
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

# the pinned SQL driver + its dependency closure (assemblies only -- no module)
COPY --from=sqldriver /drv/out/*.dll /opt/sqlclient/
ENV PIM_SQLCLIENT_DLL=/opt/sqlclient/Microsoft.Data.SqlClient.dll

WORKDIR /app
COPY SOLUTIONS/PIM4EntraPS /app/PIM4EntraPS

# Hosted defaults; the platform injects PORT/WEBSITES_PORT + the SQL connection.
ENV PIM_HOSTED=1
ENV PORT=8080
EXPOSE 8080

# StorageBackend=sql + the Azure SQL connection are supplied via app settings /
# Managed Identity at runtime (no secret baked into the image).
ENTRYPOINT ["pwsh","-NoProfile","-ExecutionPolicy","Bypass","-File","/app/PIM4EntraPS/tools/pim-manager/Open-PimManager.ps1","-Server","-Hosted","-NoLaunch"]
