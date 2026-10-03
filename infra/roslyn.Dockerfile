FROM mcr.microsoft.com/dotnet/sdk:8.0.408
COPY infra/roslyn.sh /opt/roslyn.sh
RUN chmod +x /opt/roslyn.sh
ENV DOTNET_CLI_HOME=/tmp DOTNET_NOLOGO=true DOTNET_CLI_TELEMETRY_OPTOUT=1
ENTRYPOINT ["/opt/roslyn.sh"]
