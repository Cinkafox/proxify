# --- Стадия сборки: компилируем все проекты ---
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
# Собираем по .csproj, а не по Proxify.slnx: формат .slnx поддерживается только
# .NET SDK 9+, а образ использует SDK 8.
COPY Proxy.Common/Proxy.Common.csproj Proxy.Common/
COPY Proxy.Server/Proxy.Server.csproj Proxy.Server/
COPY Proxy.Client/Proxy.Client.csproj Proxy.Client/
RUN dotnet restore Proxy.Server/Proxy.Server.csproj \
    && dotnet restore Proxy.Client/Proxy.Client.csproj
COPY . .
RUN dotnet publish Proxy.Server/Proxy.Server.csproj -c Release -o /out/server \
    && dotnet publish Proxy.Client/Proxy.Client.csproj -c Release -o /out/client

# --- Образ прокси-сервера (машина A) ---
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS server
WORKDIR /app
COPY --from=build /out/server .
EXPOSE 27015/udp
ENTRYPOINT ["dotnet", "Proxy.Server.dll"]

# --- Образ прокси-клиента (машина B) ---
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS client
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/client .
COPY docker/gamesrv.py /app/gamesrv.py
COPY docker/machine-b-entrypoint.sh /app/machine-b-entrypoint.sh
RUN chmod +x /app/machine-b-entrypoint.sh
EXPOSE 5600/udp
ENTRYPOINT ["dotnet", "Proxy.Client.dll"]
