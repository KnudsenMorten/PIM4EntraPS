# PIM Manager -- hosted on Azure Container Apps (App Service hosting is retired, IMP-47). The SAME image runs the
# tick / update / downlink / publish / dbinit jobs (they override only the command).
# Runs the Manager in HOSTED mode: binds the container port, never self-exits,
# trusts the Easy Auth principal header for identity.
#
# Build context = repo root:
#   docker build -f SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile -t <acr>/pim-manager:<tag> .
#
# REST-only: NO PowerShell modules at all (Graph/ARM/Power BI go over REST via
# PIM-Rest.ps1). The SQL data plane has no REST API, so a TDS driver is unavoidable --
# but it's a pinned .NET ASSEMBLY, NOT a PowerShell module. Stage 1 uses the .NET SDK to
# fetch a pinned Microsoft.Data.SqlClient + its dependency closure; stage 3 (runtime) copies the
# DLLs into the runtime image and PIM-SqlStore Add-Types them ($env:PIM_SQLCLIENT_DLL).
# No Install-Module, no gallery, no auto-update -- the version is frozen in the image.
#
# 🔒 IMP-49 k (§33.28, 2.4.373) -- BASE IMAGES ARE PINNED BY DIGEST. A tag (`sdk:8.0`, `powershell:7.4-...`) is a
# mutable pointer: Microsoft re-points it on every patch, so the same Dockerfile built a DIFFERENT image from one day
# to the next, and a release could not be rebuilt byte-for-byte. `image:tag@sha256:...` keeps the tag for humans and
# builds exactly the digest. The digest is the one the registry answers for that tag (the manifest LIST for the
# multi-arch SDK, the amd64 manifest for the single-arch PowerShell image; Container Apps runs linux/amd64).
# 🔁 REFRESH (deliberately, e.g. for an OS/.NET security patch) -- read the current digest, replace it here, rebuild:
#     curl -sI https://mcr.microsoft.com/v2/<repo>/manifests/<tag> \
#       -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json" \
#       | grep -i docker-content-digest
#   (<repo> = dotnet/sdk tag 8.0; powershell tag 7.4-ubuntu-22.04), or `docker buildx imagetools inspect <image>:<tag>`.
#   tests/Test-PimContainerImage.ps1 fails on any FROM that is not pinned this way.
#   Pinned 2026-09-18.

# ---- stage 1: fetch the pinned SQL driver assembly (no PS module) ----
FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:5ef85cc12cb25be6ec319a7392d1e9efd53c3bc8abb971c53d8058a473f09053 AS sqldriver
WORKDIR /drv
RUN dotnet new classlib -n shim -o shim \
 && cd shim \
 && dotnet add package Microsoft.Data.SqlClient --version 5.2.2 \
 && dotnet publish -c Release -o /drv/out

# ---- stage 2: the solution tree, PRUNED to what runs in a container (PIM §100.52, owner 2026-10-10) ----
# Owner: "the base container image should be stripped also so it doesnt contain old az cli and ps modules that we
# have now removed of the dependencies". The image used to COPY the WHOLE solution folder: the unsupported v1 code
# (legacy/, launcher/ -- Connect-AzAccount / Install-Module era), the test suites, the internal runbooks and the
# documentation screenshots shipped in every customer's image although no container ever runs or reads them.
# This stage copies the tree, removes them, and the runtime stage copies only what is left -- so they are not in ANY
# layer of the final image (a RUN rm in the runtime stage would only hide them behind a whiteout).
# KEPT on purpose: docs/img/brand (the mail logo, PIM-MailLayout.ps1 Get-PimMailBrandDir) and everything else -- the
# Manager, the jobs, tools/setup (the updater's converge step runs Set-PimAlertRecipients.ps1; the scheduler and the
# Manager load _PimScriptDoc / _PimWorkloadPrereqRunner), setup/ (the downlink runs Invoke-PimScenarioRun.ps1 /
# Invoke-PimMspFanout.ps1), engine/, sql/, templates/, config*/.
# The same pinned PowerShell image as the runtime (already pulled for stage 3: no new base image, no new digest).
# tests/Test-PimImageNoAzNoModules.ps1 proves no in-container code path reads a pruned folder, and the last RUN
# below fails the BUILD (never a running container) if a file the runtime needs went missing.
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04@sha256:62300a213a9293916333df2b014cd3a8f22fb0b0b65f2bb446aaf436bcf8c868 AS src
COPY SOLUTIONS/PIM4EntraPS /src/PIM4EntraPS
WORKDIR /src/PIM4EntraPS
RUN rm -rf tests internal legacy launcher diagnostics output \
 && find . -type d -name node_modules -prune -exec rm -rf {} + \
 && if [ -d docs ]; then find docs -mindepth 1 -maxdepth 1 ! -name img -exec rm -rf {} + ; fi \
 && if [ -d docs/img ]; then find docs/img -mindepth 1 -maxdepth 1 ! -name brand -exec rm -rf {} + ; fi \
 && test -f tools/pim-manager/Open-PimManager.ps1 \
 && test -f tools/pim-engine/update-job-entry.ps1 \
 && test -f engine/_shared/PIM-Rest.ps1 \
 && test -f setup/Invoke-PimScenarioRun.ps1 \
 && test -f tools/setup/Set-PimAlertRecipients.ps1 \
 && test -f docs/img/brand/pim-manager-512w.png

# ---- stage 3: runtime ----
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04@sha256:62300a213a9293916333df2b014cd3a8f22fb0b0b65f2bb446aaf436bcf8c868

# 🔒 PIM §100.52 (owner 2026-10-10) -- NO GALLERY / SDK POWERSHELL MODULE AND NO AZURE CLI IN THE IMAGE.
# The base image has never carried the az CLI or Az / Microsoft.Graph / ExchangeOnlineManagement (and nothing here
# installs them: framework §12.17). It DOES ship the gallery tooling -- PowerShellGet, PackageManagement,
# Microsoft.PowerShell.PSResourceGet (what Install-Module / Install-PSResource are) -- and PSReadLine (the
# interactive line editor; a container is never interactive). No code in this image uses any of them
# (tests/Test-PimImageNoAzNoModules.ps1), so they are removed: a module can no longer even be installed at runtime.
# KEPT: the in-box engine modules (Microsoft.PowerShell.Management / Utility / Security / Host / Diagnostics,
# Microsoft.PowerShell.Archive -- the Invardia update zip is unpacked with Expand-Archive, PIM-InvardiaUpdate.ps1 --
# CimCmdlets, PSDiagnostics, ThreadJob). The owner-approved module exceptions (GroupPolicy + Add-KdsRootKey,
# framework §12.17) belong to the on-prem Windows hybrid worker, which is not a container and is not built here.
# The check after the removal fails the BUILD if any such module or an az binary is still present, or if
# Expand-Archive went missing.
RUN pwsh -NoLogo -NoProfile -NonInteractive -Command '$ErrorActionPreference = "Stop"; \
    $drop = @("PowerShellGet", "PackageManagement", "Microsoft.PowerShell.PSResourceGet", "PSReadLine"); \
    $isBanned = { param($n) ($drop -contains $n) -or ($n -like "Az") -or ($n -like "Az.*") -or ($n -like "Microsoft.Graph*") -or ($n -like "ExchangeOnline*") -or ($n -like "MicrosoftTeams*") -or ($n -like "SqlServer*") }; \
    foreach ($p in @($env:PSModulePath -split ":" | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) { \
        Get-ChildItem -LiteralPath $p -Directory | Where-Object { & $isBanned $_.Name } | Remove-Item -Recurse -Force }; \
    $left = @(Get-Module -ListAvailable | Where-Object { & $isBanned $_.Name } | ForEach-Object { $_.Name } | Sort-Object -Unique); \
    if ($left.Count) { throw ("modules still in the image: " + ($left -join ", ")) }; \
    if (Get-Command az -CommandType Application -ErrorAction SilentlyContinue) { throw "the az CLI is in the image" }; \
    $null = Get-Command Expand-Archive -ErrorAction Stop; \
    Write-Host ("module strip ok; left: " + ((Get-Module -ListAvailable | ForEach-Object { $_.Name } | Sort-Object -Unique) -join ", "))'

# 🔒 §33.28 (2.4.373) -- THE IMAGE RUNS AS A NON-ROOT USER (uid/gid 10001). It ran as root: no USER at all.
# Every entry point this ONE image runs (the Manager, and the tick / update / downlink / publish / dbinit jobs, which
# override only the command) was read for what it WRITES at runtime; all of it lands in three places, and each is
# writable by this user:
#   * /app/PIM4EntraPS (the solution tree, owned by the user via COPY --chown): output/ (the Manager's output root,
#     the engine transcript output/engine-logs, the discovery/downlink state under output/) and config/ (the legacy
#     config bootstrap). /app itself (the WORKDIR, where a relative path would land) is owned by the user too.
#   * /sync/central and /sync/local: the downlink job's staging roots (PIM_SyncRootCentral / PIM_SyncRootLocal,
#     defaults of Deploy-PimDownlinkJob), created here because a non-root user cannot create a directory under /.
#   * the temp directory (/tmp, world-writable): the updater's channel.json and source archive, the publish job's
#     upload file.
# Nothing needs root: no az CLI, no apt, no Install-Module at runtime (REST only; the updater rolls over ARM and the
# registry builds the image), the listener is on 8080 (> 1024), and the managed-identity endpoint is plain HTTP.
# If an operator points PIM_LogDir or a sync root somewhere else, that path must be writable by uid 10001.
RUN groupadd --system --gid 10001 pim \
 && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/pim --shell /usr/sbin/nologin pim \
 && mkdir -p /sync/central /sync/local /app \
 && chown -R 10001:10001 /sync /app

# the pinned SQL driver + its dependency closure (assemblies only -- no module)
COPY --from=sqldriver /drv/out/*.dll /opt/sqlclient/
ENV PIM_SQLCLIENT_DLL=/opt/sqlclient/Microsoft.Data.SqlClient.dll

WORKDIR /app
# the PRUNED solution tree from stage 2 (§100.52) -- not the build context: tests / internal / legacy / launcher /
# documentation never reach a layer of this image.
COPY --from=src --chown=10001:10001 /src/PIM4EntraPS /app/PIM4EntraPS
ENV HOME=/home/pim

# 🔴 §52.12 -- THE BUILD ARG NOTHING DECLARED, SO NOTHING RECEIVED.
# Build-PimManagerImage passes --build-arg PIM_MANAGER_CONTENT_HASH=<hash> so a later deploy can
# ask "is the running image already built from this source?" and skip a pointless rebuild. This
# file never declared the ARG, so Docker discarded it and said so in EVERY build log:
#     [Warning] One or more build-args [PIM_MANAGER_CONTENT_HASH] were not consumed
# The hash therefore never reached the image, the parity check could never succeed, and every
# deploy rebuilt "to be safe" -- forever. A warning that appears in every successful build is one
# nobody reads, which is exactly why this survived.
ARG PIM_MANAGER_CONTENT_HASH=""
ENV PIM_MANAGER_CONTENT_HASH=$PIM_MANAGER_CONTENT_HASH

# Hosted defaults; the platform injects PORT/WEBSITES_PORT + the SQL connection.
ENV PIM_HOSTED=1
ENV PORT=8080
EXPOSE 8080

# StorageBackend=sql + the Azure SQL connection are supplied via app settings /
# Managed Identity at runtime (no secret baked into the image).
# Numeric, so a platform that enforces "run as non-root" can verify it without reading /etc/passwd.
USER 10001:10001
ENTRYPOINT ["pwsh","-NoProfile","-ExecutionPolicy","Bypass","-File","/app/PIM4EntraPS/tools/pim-manager/Open-PimManager.ps1","-Server","-Hosted","-NoLaunch"]
