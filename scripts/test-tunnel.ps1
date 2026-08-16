param(
    [string]$Key = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrEmpty($Key)) {
    throw "Сервер требует ключ шифрования. Задайте: pwsh scripts\test-tunnel.ps1 -Key `"my-secret`""
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# --- Вспомогательные функции (обязательно ДО основного потока: в PowerShell функции
# --- вызываются только после того, как их определение уже выполнено) ---

function Get-CipherKey {
    param([string]$passphrase)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($passphrase))
    }
    finally {
        $sha.Dispose()
    }
    $salt = New-Object byte[] 16
    [Array]::Copy($hash, 0, $salt, 0, 16)
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $passphrase, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    return , $pbkdf2.GetBytes(32)
}

function Wrap-Data {
    param([byte[]]$key, [byte[]]$plain)
    $gcm = New-Object System.Security.Cryptography.AesGcm($key, 16)
    try {
        $nonce = New-Object byte[] 12
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($nonce) } finally { $rng.Dispose() }

        $cipher = New-Object byte[] $plain.Length
        $tag = New-Object byte[] 16
        $gcm.Encrypt($nonce, $plain, $cipher, $tag)

        $out = New-Object byte[] (12 + 16 + $cipher.Length)
        [Array]::Copy($nonce, 0, $out, 0, 12)
        [Array]::Copy($tag, 0, $out, 12, 16)
        [Array]::Copy($cipher, 0, $out, 28, $cipher.Length)
        return , $out
    }
    finally {
        $gcm.Dispose()
    }
}

function Unwrap-Data {
    param([byte[]]$key, [byte[]]$blob)
    if ($blob.Length -lt 28) { throw "Слишком короткий зашифрованный кадр" }
    $nonce = New-Object byte[] 12
    $tag = New-Object byte[] 16
    [Array]::Copy($blob, 0, $nonce, 0, 12)
    [Array]::Copy($blob, 12, $tag, 0, 16)
    $cipher = New-Object byte[] ($blob.Length - 28)
    [Array]::Copy($blob, 28, $cipher, 0, $cipher.Length)

    $plain = New-Object byte[] $cipher.Length
    $gcm = New-Object System.Security.Cryptography.AesGcm($key, 16)
    try {
        $gcm.Decrypt($nonce, $cipher, $tag, $plain)
        return , $plain
    }
    finally {
        $gcm.Dispose()
    }
}

function Decode-OuterFrame {
    param([byte[]]$Frame, [byte[]]$Key)
    if ($Frame.Length -lt 3) { throw "Кадр слишком короткий" }
    if (($Frame[0] -ne 0xC0) -or ($Frame[1] -ne 0xDE)) { throw "Неверный magic кадра" }

    $type = $Frame[2]
    if ($type -ne 0x02) { throw "Получен незашифрованный кадр (0x$('{0:X2}' -f $type)), хотя ожидалось шифрование" }

    $blob = New-Object byte[] ($Frame.Length - 3)
    [Array]::Copy($Frame, 3, $blob, 0, $blob.Length)
    $inner = Unwrap-Data -Key $Key -Blob $blob

    return Decode-DataFrame -Frame $inner -WasEncrypted $true
}

function Decode-DataFrame {
    param([byte[]]$Frame, [bool]$WasEncrypted)
    if ($Frame.Length -lt 11) { throw "Внутренний кадр слишком короткий" }
    if (($Frame[0] -ne 0xC0) -or ($Frame[1] -ne 0xDE)) { throw "Неверный magic внутреннего кадра" }
    if ($Frame[2] -ne 0x01) { throw "Неверный тип внутреннего кадра" }

    $ip = "$($Frame[3]).$($Frame[4]).$($Frame[5]).$($Frame[6])"
    $port = (([int]$Frame[7]) -shl 8) -bor [int]$Frame[8]
    $len = (([int]$Frame[9]) -shl 8) -bor [int]$Frame[10]
    if ($len -gt ($Frame.Length - 11)) { throw "Длина полезной нагрузки превышает размер кадра" }

    $payload = New-Object byte[] $len
    [Array]::Copy($Frame, 11, $payload, 0, $len)

    return [pscustomobject]@{
        ClientIp     = $ip
        ClientPort   = $port
        Payload      = $payload
        PayloadText  = [Text.Encoding]::UTF8.GetString($payload)
        WasEncrypted = $WasEncrypted
    }
}

function Build-OuterFrame {
    param([string]$ClientIp, [int]$ClientPort, [byte[]]$Payload, [byte[]]$Key)

    $ipParts = $ClientIp.Split(".") | ForEach-Object { [int]$_ }
    if ($ipParts.Count -ne 4) { throw "Неверный IP: $ClientIp" }

    $inner = New-Object byte[] (11 + $Payload.Length)
    $inner[0] = 0xC0; $inner[1] = 0xDE; $inner[2] = 0x01
    $inner[3] = $ipParts[0]; $inner[4] = $ipParts[1]
    $inner[5] = $ipParts[2]; $inner[6] = $ipParts[3]
    $inner[7] = ($ClientPort -shr 8); $inner[8] = ($ClientPort -band 0xFF)
    $inner[9] = ($Payload.Length -shr 8); $inner[10] = ($Payload.Length -band 0xFF)
    [Array]::Copy($Payload, 0, $inner, 11, $Payload.Length)

    $blob = Wrap-Data -Key $Key -Plain $inner
    $outer = New-Object byte[] (3 + $blob.Length)
    $outer[0] = 0xC0; $outer[1] = 0xDE; $outer[2] = 0x02
    [Array]::Copy($blob, 0, $outer, 3, $blob.Length)
    return , $outer
}

function Build-ControlFrame {
    param([int]$Type, [byte[]]$Body, [byte[]]$Key)

    $blob = Wrap-Data -Key $Key -Plain $Body
    $out = New-Object byte[] (3 + $blob.Length)
    $out[0] = 0xC0; $out[1] = 0xDE; $out[2] = $Type
    [Array]::Copy($blob, 0, $out, 3, $blob.Length)
    return , $out
}

function Decode-EncryptedBody {
    param([byte[]]$Frame, [byte[]]$Key, [int]$ExpectedType)
    if ($Frame.Length -lt 3) { throw "Кадр слишком короткий" }
    if (($Frame[0] -ne 0xC0) -or ($Frame[1] -ne 0xDE)) { throw "Неверный magic кадра" }
    $type = $Frame[2]
    if ($type -ne $ExpectedType) {
        throw "Неверный тип кадра 0x$('{0:X2}' -f $type), ожидался 0x$('{0:X2}' -f $ExpectedType)"
    }
    $blob = New-Object byte[] ($Frame.Length - 3)
    [Array]::Copy($Frame, 3, $blob, 0, $blob.Length)
    return Unwrap-Data -Key $Key -Blob $blob
}

function Read-U32 {
    param([byte[]]$Bytes, [int]$Offset)
    return ([uint32]$Bytes[$Offset] -shl 24) -bor ([uint32]$Bytes[$Offset + 1] -shl 16) -bor `
           ([uint32]$Bytes[$Offset + 2] -shl 8) -bor [uint32]$Bytes[$Offset + 3]
}

function Build-TcpDataFrame {
    param([uint32]$ConnId, [byte[]]$Payload, [byte[]]$Key)
    $body = New-Object byte[] (4 + $Payload.Length)
    $body[0] = ($ConnId -shr 24) -band 0xFF
    $body[1] = ($ConnId -shr 16) -band 0xFF
    $body[2] = ($ConnId -shr 8) -band 0xFF
    $body[3] = $ConnId -band 0xFF
    [Array]::Copy($Payload, 0, $body, 4, $Payload.Length)
    return Build-ControlFrame -Type 6 -Body $body -Key $Key
}

# --- Основной поток теста ---

# Тест туннеля между Proxify.Server и (эмуляцией) Proxify.Client.
# Запускает Proxify.Server, играет роль реального клиента и роль туннеля прокси-клиента.
# Проверяет: клиент -> сервер -> кадр прокси-клиенту -> ответ серверу -> клиенту.
# Шифрование AES-256-GCM обязательно (сервер не запускается без ключа).
# Туннель теперь живёт на сервере: клиент шлёт кадры на его --tunnel-port,
# а сам слушает эфемерный порт (как реальный прокси-клиент).

$root = Split-Path -Parent $PSScriptRoot
$serverDll = Join-Path $root "Proxify.Server\bin\Release\net8.0\Proxify.Server.dll"

if (-not (Test-Path $serverDll)) {
    throw "Не найдена сборка: $serverDll. Сначала выполните: dotnet build Proxify.slnx -c Release"
}

$listenPort = 27015
$tunnelPort = 5600

$cipherKey = Get-CipherKey $Key
Write-Host "=== Тест туннеля (AES-256-GCM, ключ обязателен) ==="
Write-Host ""

# 0a. Негативный тест защиты от чужого клиента: сервер разрешает прокси-клиента
# только с адреса 203.0.113.9, а PING уходит с 127.0.0.1 — сервер должен отвергнуть его.
Write-Host "[0a] Проверка защиты от другого клиента (--client-ip 203.0.113.9)..."
$negPort = 27025
$negTunnelPort = 5601
$negProc = Start-Process dotnet -ArgumentList @($serverDll, "--port", "$negPort", "--tunnel-port", "$negTunnelPort", "--client-ip", "203.0.113.9", "--key", $Key) -PassThru -NoNewWindow
Start-Sleep -Milliseconds 1200

$negTunnel = New-Object System.Net.Sockets.UdpClient
$negToken = New-Object byte[] 16
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($negToken) } finally { $rng.Dispose() }
$negPing = Build-ControlFrame -Type 3 -Body $negToken -Key $cipherKey
[void]$negTunnel.Send($negPing, $negPing.Length, "127.0.0.1", $negTunnelPort)
$negTunnel.Client.ReceiveTimeout = 1200
$negEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
$rejected = $true
try {
    [void]$negTunnel.Receive([ref]$negEp)
    $rejected = $false
} catch [System.Net.Sockets.SocketException] {
    # таймаут — сервер не ответил, чужой клиент отвергнут
}
$negTunnel.Dispose()
Stop-Process -Id $negProc.Id -Force

if (-not $rejected) {
    throw "Сервер ответил на PING чужого клиента (защита --client-ip не сработала)"
}
Write-Host "    OK: сервер отверг чужого клиента (PING без ответа)."
Write-Host ""

# 0b. Основной сервер разрешает прокси-клиента с 127.0.0.1 (наш эмулируемый клиент).
$serverArgs = @($serverDll, "--port", "$listenPort", "--tunnel-port", "$tunnelPort", "--tcp", "true", "--client-ip", "127.0.0.1", "--key", $Key)

$proc = Start-Process dotnet -ArgumentList $serverArgs -PassThru -NoNewWindow
Start-Sleep -Milliseconds 1500

$tunnel = New-Object System.Net.Sockets.UdpClient
$client = New-Object System.Net.Sockets.UdpClient
$client.Connect("127.0.0.1", $listenPort)
$tcpClient = $null

try {
    # 0. Эмуляция прокси-клиента: PING на порт туннеля СЕРВЕРА — сервер определяет адрес туннеля
    $pingToken = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($pingToken) } finally { $rng.Dispose() }
    $ping = Build-ControlFrame -Type 3 -Body $pingToken -Key $cipherKey
    [void]$tunnel.Send($ping, $ping.Length, "127.0.0.1", $tunnelPort)
    Write-Host "Прокси-клиент (эмуляция): локальный порт туннеля $($tunnel.Client.LocalEndPoint.Port) (эфемерный)"
    Write-Host "[0] Прокси-клиент отправил PING на порт туннеля сервера 127.0.0.1:$tunnelPort"

    $tunnel.Client.ReceiveTimeout = 3000
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $pong = $tunnel.Receive([ref]$ep)
    if (($pong.Length -lt 3) -or ($pong[0] -ne 0xC0) -or ($pong[1] -ne 0xDE) -or ($pong[2] -ne 4)) {
        throw "Сервер не ответил PONG (ожидался кадр 0xC0 0xDE 0x04)"
    }
    Write-Host "    OK: сервер ответил PONG — адрес туннеля определён."

    # 1. Реальный клиент отправляет пакет на прокси-сервер
    $payload = [Text.Encoding]::UTF8.GetBytes("HELLO")
    [void]$client.Send($payload, $payload.Length)
    Write-Host "[1] Клиент отправил 'HELLO' на 127.0.0.1:$listenPort"

    # 2. Прокси-сервер должен доставить кадр на туннель прокси-клиента (эфемерный порт)
    $frame = $tunnel.Receive([ref]$ep)

    $decoded = Decode-OuterFrame -Frame $frame -Key $cipherKey
    Write-Host "[2] Кадр от сервера: клиент=$($decoded.ClientIp):$($decoded.ClientPort) payload='$($decoded.PayloadText)' $($decoded.WasEncrypted)"

    if ($decoded.PayloadText -ne "HELLO") {
        throw "Кадр не соответствует ожидаемому формату"
    }
    Write-Host "    OK: кадр закодирован верно, настоящий адрес клиента сохранён."

    # 3. Эмулируем прокси-клиента: отвечаем кадром обратно на порт туннеля сервера
    $reply = [Text.Encoding]::UTF8.GetBytes("REPLY")
    $rf = Build-OuterFrame -ClientIp $decoded.ClientIp -ClientPort $decoded.ClientPort -Payload $reply -Key $cipherKey
    [void]$tunnel.Send($rf, $rf.Length, "127.0.0.1", $tunnelPort)
    Write-Host "[3] Эмуляция прокси-клиента отправила кадр-ответ на порт туннеля сервера 127.0.0.1:$tunnelPort"

    # 4. Реальный клиент должен получить ответ от прокси-сервера
    $client.Client.ReceiveTimeout = 3000
    $ep2 = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $got = $client.Receive([ref]$ep2)
    $text2 = [Text.Encoding]::UTF8.GetString($got)
    Write-Host "[4] Клиент получил: '$text2' от $($ep2.Address):$($ep2.Port)"

    if ($text2 -ne "REPLY") {
        throw "Клиент получил неверный ответ"
    }
    Write-Host "    OK: ответ доставлен клиенту от адреса прокси-сервера."

    # =====================================================================
    # 5. Тест TCP-проксирования (--tcp true)
    # =====================================================================
    Write-Host ""
    Write-Host "[TCP 1] Реальный клиент подключается по TCP к 127.0.0.1:$listenPort"
    $tcpClient = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $listenPort)
    $tcpStream = $tcpClient.GetStream()
    $tcpStream.ReadTimeout = 3000

    # Сервер должен прислать кадр TcpOpen (0x05): [4] ip клиента [2] порт [4] connId
    $openFrame = $tunnel.Receive([ref]$ep)
    $openBody = Decode-EncryptedBody -Frame $openFrame -Key $cipherKey -ExpectedType 5
    $connId = Read-U32 -Bytes $openBody -Offset 6
    Write-Host "[TCP 2] Сервер уведомил прокси-клиента о TCP-соединении (connId=$connId)"

    # Данные реального клиента -> сервер -> кадр TcpData (0x06) в туннель
    $pingTcp = [Text.Encoding]::UTF8.GetBytes("PING-TCP")
    $tcpStream.Write($pingTcp, 0, $pingTcp.Length)
    $dataFrame = $tunnel.Receive([ref]$ep)
    $dataBody = Decode-EncryptedBody -Frame $dataFrame -Key $cipherKey -ExpectedType 6
    $recvConnId = Read-U32 -Bytes $dataBody -Offset 0
    $recvPayload = New-Object byte[] ($dataBody.Length - 4)
    [Array]::Copy($dataBody, 4, $recvPayload, 0, $recvPayload.Length)
    $recvText = [Text.Encoding]::UTF8.GetString($recvPayload)
    Write-Host "[TCP 3] Туннель получил от клиента: '$recvText' (connId=$recvConnId)"

    if ($recvText -ne "PING-TCP" -or $recvConnId -ne $connId) {
        throw "TCP-данные клиента переданы в туннель неверно"
    }
    Write-Host "    OK: данные TCP-клиента доставлены в туннель."

    # Эмуляция прокси-клиента: игровой сервер отвечает тем же текстом кадром TcpData
    $echo = [Text.Encoding]::UTF8.GetBytes($recvText)
    $rf = Build-TcpDataFrame -ConnId $connId -Payload $echo -Key $cipherKey
    [void]$tunnel.Send($rf, $rf.Length, "127.0.0.1", $tunnelPort)
    Write-Host "[TCP 4] Эмуляция игрового сервера ответила кадром TcpData."

    # Реальный TCP-клиент должен получить ответ
    $replyBuf = New-Object byte[] 1024
    $gotLen = $tcpStream.Read($replyBuf, 0, $replyBuf.Length)
    $gotTcp = [Text.Encoding]::UTF8.GetString($replyBuf, 0, $gotLen)
    Write-Host "[TCP 5] TCP-клиент получил: '$gotTcp'"

    if ($gotTcp -ne "PING-TCP") {
        throw "TCP-клиент получил неверный ответ"
    }
    Write-Host "    OK: ответ доставлен TCP-клиенту через туннель."
    $tcpClient.Close()
    $tcpClient = $null

    Write-Host ""
    Write-Host "ИТОГ: туннель между прокси-сервером и прокси-клиентом работает (UDP и TCP)."
}
catch {
    Write-Host ""
    Write-Host "ОШИБКА: $($_.Exception.Message)"
    Write-Host "Смотрите лог процесса прокси-сервера выше."
}
finally {
    if ($tcpClient) { $tcpClient.Close() }
    $tunnel.Close()
    $client.Close()
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
