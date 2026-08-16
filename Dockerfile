# --- Стадия сборки: компилируем все проекты ---
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
# Собираем по .csproj, а не по Proxify.slnx: формат .slnx поддерживается только
# .NET SDK 9+, а образ использует SDK 8.
COPY Proxify.Common/Proxify.Common.csproj Proxify.Common/
COPY Proxify.Server/Proxify.Server.csproj Proxify.Server/
COPY Proxify.Client/Proxify.Client.csproj Proxify.Client/
RUN dotnet restore Proxify.Server/Proxify.Server.csproj \
    && dotnet restore Proxify.Client/Proxify.Client.csproj
COPY . .
RUN dotnet publish Proxify.Server/Proxify.Server.csproj -c Release -o /out/server \
    && dotnet publish Proxify.Client/Proxify.Client.csproj -c Release -o /out/client

# --- Образ прокси-сервера (машина A) ---
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS server
WORKDIR /app
COPY --from=build /out/server .
EXPOSE 27015/udp
ENTRYPOINT ["dotnet", "Proxify.Server.dll"]

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
ENTRYPOINT ["dotnet", "Proxify.Client.dll"]
