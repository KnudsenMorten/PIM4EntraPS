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
# fetch a pinned Microsoft.Data.SqlClient + its dependency closure; stage 2 copies the
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

# ---- stage 2: runtime ----
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04@sha256:62300a213a9293916333df2b014cd3a8f22fb0b0b65f2bb446aaf436bcf8c868

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
COPY --chown=10001:10001 SOLUTIONS/PIM4EntraPS /app/PIM4EntraPS
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
