#!/bin/sh
set -eu
# Compiler analysis is separately opted in. Project MSBuild tasks are untrusted;
# this container has no network, credentials, privileges, or writable source mount.
cp -R /src /tmp/work
cd /tmp/work
project=$(find . -name '*.csproj' -print -quit)
if [ -z "$project" ]; then echo 'No C# project found' >&2; exit 2; fi
# Restore only against an empty local feed. SDK reference packs are already in
# the pinned image; external packages require explicitly supplied offline assets.
mkdir -p /tmp/offline-packages
dotnet restore "$project" --source /tmp/offline-packages --ignore-failed-sources >&2
dotnet build "$project" --no-restore -p:EnableNETAnalyzers=true -p:AnalysisLevel=latest -p:ErrorLog=/tmp/results.sarif >&2
cat /tmp/results.sarif
