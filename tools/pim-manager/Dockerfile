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
# 🔒 IMP-49 k (§33.28, 2.4.373) -- BASE IMAGES ARE PINNED BY DIGEST. A tag (`sdk:10.0-noble`) is a mutable pointer:
# Microsoft re-points it on every patch, so the same Dockerfile built a DIFFERENT image from one day to the next, and a
# release could not be rebuilt byte-for-byte. `image:tag@sha256:...` keeps the tag for humans and builds exactly the
# digest. The digest is the one the registry answers for that tag (the manifest LIST of the multi-arch SDK; Container
# Apps runs linux/amd64).
# 🔁 REFRESH (deliberately, e.g. for an OS/.NET/PowerShell security patch) -- read the current digest, replace it in EVERY
# FROM below (one base image, one digest), rebuild:
#     curl -sI https://mcr.microsoft.com/v2/dotnet/sdk/manifests/10.0-noble \
#       -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json" \
#       | grep -i docker-content-digest
#   or `docker buildx imagetools inspect mcr.microsoft.com/dotnet/sdk:10.0-noble`.
#   tests/Test-PimContainerImage.ps1 fails on any FROM that is not pinned this way.
#   History: pinned 2026-09-18 on sdk:8.0 + powershell:7.4-ubuntu-22.04; 2026-11-10 (IMAGE-PATCH-1) the frozen
#   powershell:7.4 runtime got a GitHub PowerShell 7.4.22 .deb at build.
# 🔒 NET10-PS76 (framework IMAGE-PATCH-1 point 0 + 1b, owner 2026-11-10) -- ONE BASE IMAGE: mcr.microsoft.com/dotnet/sdk:
#   10.0-noble, for every stage. .NET 8 and PowerShell 7.4 reach end of support 2026-11-10 (owner: "each solution must move
#   to .net 10 + latest ps"). The PowerShell images are no longer rebuilt by Microsoft (the 7.4 tag was frozen on a 2024
#   Ubuntu layer); the .NET SDK image IS rebuilt on every .NET / OS security update and it SHIPS PowerShell (7.6, installed
#   as a .NET global tool under /usr/share/powershell, /usr/bin/pwsh links to it, running on the image's own .NET 10
#   runtime). So a digest refresh patches the OS, .NET AND PowerShell together -- nothing is downloaded from GitHub or
#   packages.microsoft.com (owner: "i dont understand why we download ps from ms if it is included in image").
#   Digest read 2026-11-10 from the MCR v2 API: sdk 10.0.403 / runtime 10.0.14 / PowerShell 7.6.9 on Ubuntu 24.04.

# 🔒 SEC-106 (as the sign-in front 1.4.3) -- EVERY NuGet RESTORE IS LOCKED. Each .NET stage restores a committed carrier
# project (tools/pim-manager/nuget/<x>/*.csproj: one pinned PackageReference, RestorePackagesWithLockFile=true) against
# its committed packages.lock.json with `dotnet restore --locked-mode`: the whole dependency closure AND each package's
# content hash are frozen, so a transitive dependency can never move under the same top-level version and a re-published
# package is refused. It used to be `dotnet new classlib` + `dotnet add package` (no lock file: the closure was resolved
# fresh on every build). Same project shape, so the published DLLs are the same versions as before.
# Move a version on purpose only: edit the .csproj, `dotnet restore` it (the lock file is rewritten), commit both.
# tests/Test-PimContainerImage.ps1 fails on an unlocked restore or a lock file that disagrees with the .csproj.

# ---- stage 1: fetch the pinned SQL driver assembly (no PS module) ----
# PINNED: Microsoft.Data.SqlClient 6.1.8 (tools/pim-manager/nuget/sqlclient/shim.csproj + its packages.lock.json)
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS sqldriver
WORKDIR /drv/shim
COPY SOLUTIONS/PIM4EntraPS/tools/pim-manager/nuget/sqlclient/shim.csproj SOLUTIONS/PIM4EntraPS/tools/pim-manager/nuget/sqlclient/packages.lock.json ./
# NET10-PS76: a RID-less publish puts the PLATFORM-NEUTRAL Microsoft.Data.SqlClient.dll at the root -- a stub that throws
# "Microsoft.Data.SqlClient is not supported on this platform" -- and the working Linux driver under
# runtimes/unix/lib/<tfm>/. Only the root *.dll files reach the image, so the unix driver is copied over the stub here and
# the build FAILS unless the root file is that driver. (Measured 2026-11-10 on the runner: root 104 types, no TdsParser;
# runtimes/unix 656 types. Until now pwsh's own System.Data.SqlClient was always found first, so the stub was never loaded.)
RUN dotnet restore shim.csproj --locked-mode \
 && dotnet publish shim.csproj -c Release -o /drv/out --no-restore \
 && test -f /drv/out/Microsoft.Data.SqlClient.dll \
 && cp /drv/out/runtimes/unix/lib/net*/Microsoft.Data.SqlClient.dll /drv/out/Microsoft.Data.SqlClient.dll \
 && cmp -s /drv/out/runtimes/unix/lib/net*/Microsoft.Data.SqlClient.dll /drv/out/Microsoft.Data.SqlClient.dll

# ---- stage 1b: the pinned PDF library for the as-built document (PIM §100.61, owner 2026-10-10) ----
# PDFsharp + MigraDoc (MIT, empira; NOT QuestPDF) -- .NET ASSEMBLIES, no PowerShell module, version frozen here. The same
# SDK image as stage 1 (no new base image). engine/_shared/PIM-AsBuilt.ps1 Add-Types them from $env:PIM_PDF_DLL_DIR.
# The build FAILS if an assembly the renderer loads is missing. Licence: tools/pim-manager/third-party/ (copied below).
# PINNED: PDFsharp-MigraDoc 6.2.4 (tools/pim-manager/nuget/pdf/pdfshim.csproj + its packages.lock.json)
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS pdflib
WORKDIR /pdf/pdfshim
COPY SOLUTIONS/PIM4EntraPS/tools/pim-manager/nuget/pdf/pdfshim.csproj SOLUTIONS/PIM4EntraPS/tools/pim-manager/nuget/pdf/packages.lock.json ./
RUN dotnet restore pdfshim.csproj --locked-mode \
 && dotnet publish pdfshim.csproj -c Release -o /pdf/out --no-restore \
 && rm -f /pdf/out/pdfshim.* \
 && test -f /pdf/out/MigraDoc.Rendering.dll \
 && test -f /pdf/out/MigraDoc.DocumentObjectModel.dll \
 && test -f /pdf/out/PdfSharp.dll

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
# The same pinned base image as every other stage (NET10-PS76: one base image, one digest).
# tests/Test-PimImageNoAzNoModules.ps1 proves no in-container code path reads a pruned folder, and the last RUN
# below fails the BUILD (never a running container) if a file the runtime needs went missing.
# tools/pim-manager/nuget (SEC-106: the carrier projects stages 1 / 1b restore) is build input only -- pruned as well.
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS src
COPY SOLUTIONS/PIM4EntraPS /src/PIM4EntraPS
WORKDIR /src/PIM4EntraPS
RUN rm -rf tests internal legacy launcher diagnostics output tools/pim-manager/nuget \
 && find . -type d -name node_modules -prune -exec rm -rf {} + \
 && if [ -d docs ]; then find docs -mindepth 1 -maxdepth 1 ! -name img -exec rm -rf {} + ; fi \
 && if [ -d docs/img ]; then find docs/img -mindepth 1 -maxdepth 1 ! -name brand -exec rm -rf {} + ; fi \
 && test -f tools/pim-manager/Open-PimManager.ps1 \
 && test -f tools/pim-engine/update-job-entry.ps1 \
 && test -f engine/_shared/PIM-Rest.ps1 \
 && test -f tools/setup/Invoke-PimScenarioRun.ps1 \
 && test -f tools/setup/Set-PimAlertRecipients.ps1 \
 && test -f docs/img/brand/pim-manager-512w.png \
 && echo "7da195a74c55bef988d0d48f9508bd5d849425c1770dba5d7bfc6ce9ed848954  tools/pim-manager/third-party/fonts/DejaVuSans.ttf" | sha256sum -c - \
 && echo "e6476c1b80502924294eed40894c5b18e06c181444ca953e5334262df9c27724  tools/pim-manager/third-party/fonts/DejaVuSans-Bold.ttf" | sha256sum -c -
# ^ §100.61: the PDF font is VENDORED in the repo (DejaVu Sans 2.37, tools/pim-manager/third-party/fonts, pinned by SHA-256
#   in third-party/NOTICE.txt) -- no package manager and no extra network at build time; a changed file fails the build.

# ---- stage 3: runtime ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e

# 🔒 IMAGE-PATCH-1 (framework, owner 2026-11-10: "we immediately patch images when this happens") -- PATCH THE BASE AT BUILD.
# A customer's Defender scan of 3.0.70 listed ~70 fixable High/Critical findings in the base layer. This one RUN, before
# anything else in the stage, upgrades every Ubuntu package to the current noble-updates / noble-security level
# (non-interactive) and removes the apt lists in the same RUN (nothing of it stays in a layer).
# NET10-PS76: PowerShell is NOT installed or replaced here any more -- it is the SDK image's own (see the REFRESH note at
# the top: a digest refresh moves .NET and PowerShell together). The build FAILS unless the pwsh the image runs is 7.6.x on
# a .NET 10 runtime: a base whose PowerShell moved to another minor, or lost it, is a red build, never a running container.
# The module strip below runs on this PowerShell.
RUN export DEBIAN_FRONTEND=noninteractive \
 && apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && v="$(pwsh -NoLogo -NoProfile -NonInteractive -Command '"$($PSVersionTable.PSVersion)|$([Environment]::Version.Major)"')" \
 && echo "pwsh|runtime major: $v" \
 && case "$v" in 7.6.*"|10") ;; *) echo "expected PowerShell 7.6.x on .NET 10, found $v" >&2; exit 1 ;; esac

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
# NET10-PS76: the noble SDK base already has two users -- 'ubuntu' (1000) and the .NET images' 'app' ($APP_UID 1654) --
# neither collides with 10001, and neither is used: the image still runs as its own 'pim' user.
RUN groupadd --system --gid 10001 pim \
 && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/pim --shell /usr/sbin/nologin pim \
 && mkdir -p /sync/central /sync/local /app \
 && chown -R 10001:10001 /sync /app

# the pinned SQL driver + its dependency closure (assemblies only -- no module)
COPY --from=sqldriver /drv/out/*.dll /opt/sqlclient/
ENV PIM_SQLCLIENT_DLL=/opt/sqlclient/Microsoft.Data.SqlClient.dll

# §100.61: the pinned PDF library + its licence, and the font (assemblies and files only -- no module)
COPY --from=pdflib /pdf/out/*.dll /opt/pdf/
COPY --from=src /src/PIM4EntraPS/tools/pim-manager/third-party/PDFsharp-MigraDoc-LICENSE.txt /opt/pdf/PDFsharp-MigraDoc-LICENSE.txt
COPY --from=src /src/PIM4EntraPS/tools/pim-manager/third-party/fonts/ /opt/pdf/fonts/
ENV PIM_PDF_DLL_DIR=/opt/pdf
ENV PIM_PDF_FONT_DIR=/opt/pdf/fonts

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
