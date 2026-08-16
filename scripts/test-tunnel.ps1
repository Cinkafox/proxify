param(
    [string]$Key = "",
    [string]$Config = "",
    [int]$TunnelPort = 5600,
    [int]$Port = 27015,
    [int]$GamePort = 7777,
    [switch]$Tcp = $true,
    [switch]$NoTcp
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if ([string]::IsNullOrEmpty($Key)) {
    throw "Требуется закрытый ключ клиента. Задайте: pwsh scripts\test-tunnel.ps1 -Key path\to\client-private.pem"
}
if (-not (Test-Path -LiteralPath $Key)) {
    throw "Файл ключа не найден: $Key"
}

# --- Вспомогательные функции (обязательно ДО основного потока) ---

function Read-U16BE {
    param([byte[]]$Bytes, [int]$Offset)
    return (([int]$Bytes[$Offset] -shl 8) -bor [int]$Bytes[$Offset + 1])
}

function Read-U32BE {
    param([byte[]]$Bytes, [int]$Offset)
    return ([uint32]$Bytes[$Offset] -shl 24) -bor ([uint32]$Bytes[$Offset + 1] -shl 16) -bor `
           ([uint32]$Bytes[$Offset + 2] -shl 8) -bor [uint32]$Bytes[$Offset + 3]
}

function Write-U16BE {
    param([int]$Value)
    return , [byte[]]@((($Value -shr 8) -band 0xFF), ($Value -band 0xFF))
}

function Write-U32BE {
    param([uint32]$Value)
    return , [byte[]]@(
        (($Value -shr 24) -band 0xFF), (($Value -shr 16) -band 0xFF),
        (($Value -shr 8) -band 0xFF), ($Value -band 0xFF))
}

function Concat-Bytes {
    param([object[]]$Parts)
    $total = 0
    foreach ($p in $Parts) { $total += $p.Length }
    $out = New-Object byte[] $total
    $o = 0
    foreach ($p in $Parts) {
        [Array]::Copy($p, 0, $out, $o, $p.Length)
        $o += $p.Length
    }
    return , $out
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

        return , (Concat-Bytes @($nonce, $tag, $cipher))
    }
    finally {
        $gcm.Dispose()
    }
}

function Unwrap-Data {
    param([byte[]]$key, [byte[]]$blob)
    if ($blob.Length -lt 28) { throw "Слишком короткий зашифрованный блок" }
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

function Receive-FromSocket {
    param([System.Net.Sockets.UdpClient]$Socket, [int]$TimeoutMs, [string]$What)
    $Socket.Client.ReceiveTimeout = $TimeoutMs
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $data = $Socket.Receive([ref]$ep)
    if ($data.Length -lt 3 -or $data[0] -ne 0xC0 -or $data[1] -ne 0xDE) {
        throw "${What}: получен не наш кадр (нет magic)"
    }
    return , $data
}

function Build-AuthFrame {
    param(
        [System.Security.Cryptography.ECDsa]$Key,
        [System.Security.Cryptography.ECDiffieHellman]$Ecdh,
        [byte[]]$Nonce
    )
    $params = $Ecdh.ExportParameters($false)
    $x = $params.Q.X
    $y = $params.Q.Y
    $info = [Text.Encoding]::UTF8.GetBytes("proxify-auth-v1")
    $payload = Concat-Bytes @($info, $x, $y, $Nonce)
    $sig = $Key.SignData($payload, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)

    $body = Concat-Bytes @([byte[]]@(1), $x, $y, $Nonce, $sig)
    return , (Concat-Bytes @([byte[]]@(0xC0, 0xDE, 0x08), $body))
}

function Derive-SessionKey {
    param(
        [System.Security.Cryptography.ECDiffieHellman]$Ecdh,
        [byte[]]$sX,
        [byte[]]$sY
    )
    $peer = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
        $ecp = [System.Security.Cryptography.ECParameters]::new()
        $ecp.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
        $q = [System.Security.Cryptography.ECPoint]::new()
        $q.X = $sX
        $q.Y = $sY
        $ecp.Q = $q
        $peer.ImportParameters($ecp)
        $secret = $Ecdh.DeriveRawSecretAgreement($peer.PublicKey)
        try {
            return , [System.Security.Cryptography.HKDF]::DeriveKey(
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                $secret, 32, [Text.Encoding]::UTF8.GetBytes("proxify-session-v1"))
        }
        finally {
            if ($secret) { [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($secret) }
        }
    }
    finally {
        $peer.Dispose()
    }
}

function Build-EncryptedDataFrame {
    param([string]$ClientIp, [int]$ClientPort, [byte[]]$Payload, [byte[]]$Key)
    $ipParts = $ClientIp.Split(".") | ForEach-Object { [int]$_ }
    if ($ipParts.Count -ne 4) { throw "Неверный IP: $ClientIp" }
    $inner = Concat-Bytes @(
        [byte[]]@(0xC0, 0xDE, 0x01),
        [byte[]]@($ipParts[0], $ipParts[1], $ipParts[2], $ipParts[3]),
        (Write-U16BE $ClientPort),
        (Write-U16BE $Payload.Length),
        $Payload)
    $blob = Wrap-Data -Key $Key -Plain $inner
    return , (Concat-Bytes @([byte[]]@(0xC0, 0xDE, 0x02), $blob))
}

function Decode-DataFrame {
    param([byte[]]$Frame, [byte[]]$Key)
    if ($Frame.Length -lt 3) { throw "Кадр данных слишком короткий" }
    $type = $Frame[2]
    if ($type -ne 0x02) { throw "Ожидался зашифрованный кадр (0x02), получен 0x$('{0:X2}' -f $type)" }
    $blob = New-Object byte[] ($Frame.Length - 3)
    [Array]::Copy($Frame, 3, $blob, 0, $blob.Length)
    $inner = Unwrap-Data -Key $Key -Blob $blob

    if ($inner.Length -lt 11 -or $inner[0] -ne 0xC0 -or $inner[1] -ne 0xDE -or $inner[2] -ne 0x01) {
        throw "Внутренний кадр данных неверного формата"
    }
    $ip = "$($inner[3]).$($inner[4]).$($inner[5]).$($inner[6])"
    $port = Read-U16BE -Bytes $inner -Offset 7
    $len = Read-U16BE -Bytes $inner -Offset 9
    if ($len -gt ($inner.Length - 11)) { throw "Длина полезной нагрузки превышает размер кадра" }
    $payload = New-Object byte[] $len
    [Array]::Copy($inner, 11, $payload, 0, $len)
    return , [pscustomobject]@{
        ClientIp    = $ip
        ClientPort  = $port
        Payload     = $payload
        PayloadText = [Text.Encoding]::UTF8.GetString($payload)
    }
}

function Build-ControlFrame {
    param([int]$Type, [byte[]]$Body, [byte[]]$Key)
    $blob = Wrap-Data -Key $Key -Plain $Body
    return , (Concat-Bytes @([byte[]]@(0xC0, 0xDE, [byte]$Type), $blob))
}

function Decode-EncryptedBody {
    param([byte[]]$Frame, [byte[]]$Key, [int]$ExpectedType)
    if ($Frame.Length -lt 3) { throw "Кадр слишком короткий" }
    $type = $Frame[2]
    if ($type -ne $ExpectedType) {
        throw "Неверный тип кадра 0x$('{0:X2}' -f $type), ожидался 0x$('{0:X2}' -f $ExpectedType)"
    }
    $blob = New-Object byte[] ($Frame.Length - 3)
    [Array]::Copy($Frame, 3, $blob, 0, $blob.Length)
    return Unwrap-Data -Key $Key -Blob $blob
}

function Build-TcpDataFrame {
    param([uint32]$ConnId, [byte[]]$Payload, [byte[]]$Key)
    $body = Concat-Bytes @((Write-U32BE $ConnId), $Payload)
    return Build-ControlFrame -Type 6 -Body $body -Key $Key
}

function Build-TcpCloseFrame {
    param([uint32]$ConnId, [byte[]]$Key)
    return Build-ControlFrame -Type 7 -Body (Write-U32BE $ConnId) -Key $Key
}

# --- Подготовка ---

$root = Split-Path -Parent $PSScriptRoot
$serverDll = Join-Path $root "Proxify.Server\bin\Release\net8.0\Proxify.Server.dll"
if (-not (Test-Path $serverDll)) {
    throw "Не найдена сборка: $serverDll. Сначала выполните: dotnet build Proxify.slnx -c Release"
}

# Загружаем закрытый ключ клиента и строим конфиг сервера (если не задан).
$keyPem = Get-Content -LiteralPath $Key -Raw
$identity = [System.Security.Cryptography.ECDsa]::Create()
$identity.ImportFromPem($keyPem)

$workDir = Join-Path $env:TEMP "proxify-test-$(Get-Random)"
New-Item -ItemType Directory -Path $workDir | Out-Null

$tcpEnabled = -not $NoTcp
$configPath = $Config
if ([string]::IsNullOrEmpty($configPath)) {
    $publicPem = $identity.ExportSubjectPublicKeyInfoPem()
    $publicKeyFile = Join-Path $workDir "client-public.pem"
    Set-Content -LiteralPath $publicKeyFile -Value $publicPem -NoNewline
    $configPath = Join-Path $workDir "server.json"
    $cfgJson = @{
        clients = @(
            @{
                name       = "test"
                publicKey  = "client-public.pem"
                port       = $Port
                gameIp     = "127.0.0.1"
                gamePort   = $GamePort
                capture    = $true
                aliases    = $false
                tcp        = $tcpEnabled
                tcpPort    = $Port
            }
        )
    } | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $configPath -Value $cfgJson
}

Write-Host "=== Тест туннеля (ECDSA P-256 + ECDH P-256 + HKDF + AES-256-GCM) ==="
Write-Host "Конфиг сервера : $configPath"
Write-Host "Закрытый ключ  : $Key"
Write-Host "Порт туннеля   : $TunnelPort"
Write-Host "Порт игроков   : $(if ([string]::IsNullOrEmpty($Config)) { $Port } else { '(из конфига)' })"
Write-Host ""

$serverLog = Join-Path $workDir "server.out.log"
$serverErr = Join-Path $workDir "server.err.log"
$proc = Start-Process dotnet -ArgumentList @($serverDll, "--config", $configPath, "--tunnel-port", "$TunnelPort") `
    -PassThru -NoNewWindow -RedirectStandardOutput $serverLog -RedirectStandardError $serverErr
Start-Sleep -Milliseconds 1500

$tunnel = $null
$player = $null
$tcpClient = $null
$cfg = $null

try {
    # Узнаём фактический порт игроков из конфига.
    $rawCfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $playerPort = [int]$rawCfg.clients[0].port

    # --- 0. Отрицательный тест: чужой ключ должен быть отвергнут ---
    Write-Host "[0] Негативный тест: Auth чужим ключом должен быть отвергнут..."
    $badKey = [System.Security.Cryptography.ECDsa]::Create()
    try {
        $badKey.GenerateKey([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $badEcdh = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        try {
            $badNonce = New-Object byte[] 16
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($badNonce) } finally { $rng.Dispose() }
            $badAuth = Build-AuthFrame -Key $badKey -Ecdh $badEcdh -Nonce $badNonce
            $negTunnel = New-Object System.Net.Sockets.UdpClient
            try {
                [void]$negTunnel.Send($badAuth, $badAuth.Length, "127.0.0.1", $TunnelPort)
                $negTunnel.Client.ReceiveTimeout = 1200
                $negEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $rejected = $true
                try {
                    [void]$negTunnel.Receive([ref]$negEp)
                    $rejected = $false
                } catch [System.Net.Sockets.SocketException] {
                    # таймаут — сервер не ответил, чужой клиент отвергнут
                }
            }
            finally {
                $negTunnel.Dispose()
            }
        }
        finally {
            $badEcdh.Dispose()
        }
    }
    finally {
        $badKey.Dispose()
    }
    if (-not $rejected) {
        throw "Сервер ответил на Auth чужого ключа (защита не сработала)"
    }
    Write-Host "    OK: сервер отверг Auth чужого ключа."

    # --- 1. Рукопожатие Auth / AuthAck ---
    $tunnel = New-Object System.Net.Sockets.UdpClient
    $nonce = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($nonce) } finally { $rng.Dispose() }
    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)

    $auth = Build-AuthFrame -Key $identity -Ecdh $ecdh -Nonce $nonce
    [void]$tunnel.Send($auth, $auth.Length, "127.0.0.1", $TunnelPort)
    Write-Host "[1] Auth отправлен, локальный порт туннеля $($tunnel.Client.LocalEndPoint.Port)"

    $ack = Receive-FromSocket -Socket $tunnel -TimeoutMs 3000 -What "AuthAck"
    if ($ack[2] -ne 0x09) { throw "Ожидался кадр AuthAck (0x09), получен 0x$('{0:X2}' -f $ack[2])" }
    if ($ack.Length -lt 3 + 32 + 32 + 28) { throw "AuthAck слишком короткий" }
    $sX = New-Object byte[] 32
    $sY = New-Object byte[] 32
    [Array]::Copy($ack, 3, $sX, 0, 32)
    [Array]::Copy($ack, 35, $sY, 0, 32)
    $wrappedProof = New-Object byte[] ($ack.Length - 67)
    [Array]::Copy($ack, 67, $wrappedProof, 0, $wrappedProof.Length)

    $sessionKey = Derive-SessionKey -Ecdh $ecdh -sX $sX -sY $sY

    $proof = Unwrap-Data -Key $sessionKey -Blob $wrappedProof
    if ($proof.Length -ne 23) { throw "Неверная длина proof: $($proof.Length)" }
    for ($i = 0; $i -lt 16; $i++) {
        if ($proof[$i] -ne $nonce[$i]) { throw "echo nonce не совпадает" }
    }
    $flags = $proof[16]
    $gameIp = "$($proof[17]).$($proof[18]).$($proof[19]).$($proof[20])"
    $gamePort = Read-U16BE -Bytes $proof -Offset 21
    Write-Host "[2] AuthAck получен: сессионный ключ + конфиг (игра $gameIp`:$gamePort, flags=0x$('{0:X2}' -f $flags))"
    if ($gamePort -ne $GamePort) { throw "Игровой порт из конфига не совпадает" }
    Write-Host "    OK: конфиг от сервера получен и расшифрован."

    # --- 2. PING / PONG ---
    $pingToken = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($pingToken) } finally { $rng.Dispose() }
    $ping = Build-ControlFrame -Type 3 -Body $pingToken -Key $sessionKey
    [void]$tunnel.Send($ping, $ping.Length, "127.0.0.1", $TunnelPort)
    $pong = Receive-FromSocket -Socket $tunnel -TimeoutMs 3000 -What "PONG"
    $pongBody = Decode-EncryptedBody -Frame $pong -Key $sessionKey -ExpectedType 4
    if ($pongBody.Length -ne 17) { throw "Неверный формат PONG" }
    for ($i = 0; $i -lt 16; $i++) {
        if ($pongBody[$i] -ne $pingToken[$i]) { throw "Маркер PONG не совпадает с PING" }
    }
    $tcpFlag = $pongBody[16] -eq 1
    Write-Host "[3] PONG OK (tcp-флаг из PONG: $tcpFlag)."

    # --- 3. UDP: игрок -> сервер -> туннель -> игрок ---
    $player = New-Object System.Net.Sockets.UdpClient
    $player.Connect("127.0.0.1", $playerPort)
    $hello = [Text.Encoding]::UTF8.GetBytes("HELLO")
    [void]$player.Send($hello, $hello.Length)
    Write-Host "[4] Игрок отправил 'HELLO' на 127.0.0.1:$playerPort"

    $frame = Receive-FromSocket -Socket $tunnel -TimeoutMs 3000 -What "кадр данных"
    $decoded = Decode-DataFrame -Frame $frame -Key $sessionKey
    Write-Host "[5] Кадр от сервера: клиент=$($decoded.ClientIp):$($decoded.ClientPort) payload='$($decoded.PayloadText)'"
    if ($decoded.PayloadText -ne "HELLO") { throw "Кадр не соответствует ожидаемому формату" }

    $reply = [Text.Encoding]::UTF8.GetBytes("REPLY")
    $rf = Build-EncryptedDataFrame -ClientIp $decoded.ClientIp -ClientPort $decoded.ClientPort -Payload $reply -Key $sessionKey
    [void]$tunnel.Send($rf, $rf.Length, "127.0.0.1", $TunnelPort)
    Write-Host "[6] Эмуляция прокси-клиента отправила кадр-ответ."

    $player.Client.ReceiveTimeout = 3000
    $playerEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $got = $player.Receive([ref]$playerEp)
    $gotText = [Text.Encoding]::UTF8.GetString($got)
    Write-Host "[7] Игрок получил: '$gotText' от $($playerEp.Address):$($playerEp.Port)"
    if ($gotText -ne "REPLY") { throw "Игрок получил неверный ответ" }
    Write-Host "    OK: UDP-путь через туннель работает."

    # --- 4. TCP (если включено в конфиге) ---
    if ($tcpEnabled) {
        Write-Host "[TCP 1] Игрок подключается по TCP к 127.0.0.1:$playerPort"
        $tcpClient = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $playerPort)
        $tcpStream = $tcpClient.GetStream()
        $tcpStream.ReadTimeout = 3000

        $openFrame = Receive-FromSocket -Socket $tunnel -TimeoutMs 3000 -What "TcpOpen"
        $openBody = Decode-EncryptedBody -Frame $openFrame -Key $sessionKey -ExpectedType 5
        if ($openBody.Length -ne 10) { throw "Неверный формат TcpOpen" }
        $connId = Read-U32BE -Bytes $openBody -Offset 6
        Write-Host "[TCP 2] Сервер уведомил прокси-клиента о TCP-соединении (connId=$connId)"

        $pingTcp = [Text.Encoding]::UTF8.GetBytes("PING-TCP")
        $tcpStream.Write($pingTcp, 0, $pingTcp.Length)
        $dataFrame = Receive-FromSocket -Socket $tunnel -TimeoutMs 3000 -What "TcpData"
        $dataBody = Decode-EncryptedBody -Frame $dataFrame -Key $sessionKey -ExpectedType 6
        if ($dataBody.Length -lt 4) { throw "Неверный формат TcpData" }
        $recvConnId = Read-U32BE -Bytes $dataBody -Offset 0
        $recvPayload = New-Object byte[] ($dataBody.Length - 4)
        [Array]::Copy($dataBody, 4, $recvPayload, 0, $recvPayload.Length)
        $recvText = [Text.Encoding]::UTF8.GetString($recvPayload)
        Write-Host "[TCP 3] Туннель получил от игрока: '$recvText' (connId=$recvConnId)"
        if ($recvText -ne "PING-TCP" -or $recvConnId -ne $connId) { throw "TCP-данные переданы в туннель неверно" }

        $echo = [Text.Encoding]::UTF8.GetBytes($recvText)
        $echoFrame = Build-TcpDataFrame -ConnId $connId -Payload $echo -Key $sessionKey
        [void]$tunnel.Send($echoFrame, $echoFrame.Length, "127.0.0.1", $TunnelPort)
        Write-Host "[TCP 4] Эмуляция игрового сервера ответила кадром TcpData."

        $replyBuf = New-Object byte[] 1024
        $gotLen = $tcpStream.Read($replyBuf, 0, $replyBuf.Length)
        $gotTcp = [Text.Encoding]::UTF8.GetString($replyBuf, 0, $gotLen)
        Write-Host "[TCP 5] Игрок (TCP) получил: '$gotTcp'"
        if ($gotTcp -ne "PING-TCP") { throw "Игрок (TCP) получил неверный ответ" }
        Write-Host "    OK: TCP-путь через туннель работает."

        # --- 5b. Большой HTTP-подобный поток (> MaxFramePayload=1400): батчер дробит кадры ---
        $bigHeader = "HTTP/1.1 200 OK`r`nContent-Length: 3000`r`n`r`n"
        $big = [Text.Encoding]::UTF8.GetBytes(($bigHeader + ("x" * 3000)))
        $tcpStream.Write($big, 0, $big.Length)
        Write-Host "[TCP 7] Игрок (TCP) отправил поток $($big.Length) байт (HTTP-ответ + тело 3000 байт)..."

        $received = New-Object System.Collections.Generic.List[byte]
        $deadline = (Get-Date).AddSeconds(5)
        while ($received.Count -lt $big.Length -and (Get-Date) -lt $deadline) {
            $bigFrame = Receive-FromSocket -Socket $tunnel -TimeoutMs 1000 -What "TcpData (большой поток)"
            $bigBody = Decode-EncryptedBody -Frame $bigFrame -Key $sessionKey -ExpectedType 6
            $bigRecvConnId = Read-U32BE -Bytes $bigBody -Offset 0
            if ($bigRecvConnId -ne $connId) { throw "TcpData большого потока с неверным connId" }
            [byte[]]$bigPayload = New-Object byte[] ($bigBody.Length - 4)
            [Array]::Copy($bigBody, 4, $bigPayload, 0, $bigPayload.Length)
            $received.AddRange($bigPayload)
        }
        if ($received.Count -ne $big.Length) { throw "Большой поток получен не полностью: $($received.Count)/$($big.Length)" }
        $receivedBigText = [Text.Encoding]::UTF8.GetString($received.ToArray())
        if ($receivedBigText -ne ([Text.Encoding]::UTF8.GetString($big))) { throw "Содержимое большого потока повреждено" }
        Write-Host "    OK: большой поток ($($big.Length) байт) доставлен целым, батчер корректно дробит кадры."

        $tcpClient.Close()
        $tcpClient = $null
        $closeFrame = Receive-FromSocket -Socket $tunnel -TimeoutMs 3000 -What "TcpClose"
        $closeBody = Decode-EncryptedBody -Frame $closeFrame -Key $sessionKey -ExpectedType 7
        $closeConnId = Read-U32BE -Bytes $closeBody -Offset 0
        if ($closeConnId -ne $connId) { throw "TcpClose с неверным connId" }
        Write-Host "[TCP 6] Сервер уведомил о закрытии соединения (connId=$connId)."
    }

    Write-Host ""
    Write-Host "ИТОГ: туннель работает (Auth, PING/PONG, UDP и TCP)."
}
catch {
    Write-Host ""
    Write-Host "ОШИБКА: $($_.Exception.Message)"
    if (Test-Path $serverLog) {
        Write-Host "--- Лог прокси-сервера ---"
        Get-Content $serverLog | Select-Object -Last 15
    }
}
finally {
    $ecdh.Dispose()
    $identity.Dispose()
    if ($tcpClient) { $tcpClient.Close() }
    if ($tunnel) { $tunnel.Close() }
    if ($player) { $player.Close() }
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
