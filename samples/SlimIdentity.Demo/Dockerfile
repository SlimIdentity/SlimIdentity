# Playground / Breakme container of the demo. Build context: the repository root (see docker-compose.yml).
# Published as a regular (JIT) app – the Native AOT check runs in CI; AOT inside Docker would need the clang toolchain.

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /repo
COPY . .
RUN dotnet publish samples/SlimIdentity.Demo -c Release -o /app -p:PublishAot=false -p:MinVerSkip=true

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
# the aspnet image listens on 8080 (HTTP_PORTS) as the non-root user "app"
EXPOSE 8080
USER app
ENTRYPOINT ["dotnet", "SlimIdentity.Demo.dll"]
