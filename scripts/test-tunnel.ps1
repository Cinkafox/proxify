param(
    [string]$Key = ""
)

$ErrorActionPreference = "Stop"

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
    param([byte[]]$Frame, [byte[]]$Key, [bool]$ExpectEncrypted)
    if ($Frame.Length -lt 3) { throw "Кадр слишком короткий" }
    if (($Frame[0] -ne 0xC0) -or ($Frame[1] -ne 0xDE)) { throw "Неверный magic кадра" }

    $type = $Frame[2]
    $inner = $null
    $wasEncrypted = $false

    if ($type -eq 0x02) {
        if (-not $ExpectEncrypted) { throw "Получен зашифрованный кадр (0x02), хотя шифрование не ожидалось" }
        if ($null -eq $Key) { throw "Получен зашифрованный кадр, но ключ не задан" }
        $blob = New-Object byte[] ($Frame.Length - 3)
        [Array]::Copy($Frame, 3, $blob, 0, $blob.Length)
        $inner = Unwrap-Data -Key $Key -Blob $blob
        $wasEncrypted = $true
    }
    elseif ($type -eq 0x01) {
        if ($ExpectEncrypted) { throw "Получен незашифрованный кадр (0x01), хотя ожидалось шифрование" }
        $inner = $Frame
    }
    else {
        throw "Неизвестный тип кадра: 0x$('{0:X2}' -f $type)"
    }

    return Decode-DataFrame -Frame $inner -WasEncrypted $wasEncrypted
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
    param([string]$ClientIp, [int]$ClientPort, [byte[]]$Payload, [byte[]]$Key, [bool]$Encrypt)

    $ipParts = $ClientIp.Split(".") | ForEach-Object { [int]$_ }
    if ($ipParts.Count -ne 4) { throw "Неверный IP: $ClientIp" }

    $inner = New-Object byte[] (11 + $Payload.Length)
    $inner[0] = 0xC0; $inner[1] = 0xDE; $inner[2] = 0x01
    $inner[3] = $ipParts[0]; $inner[4] = $ipParts[1]
    $inner[5] = $ipParts[2]; $inner[6] = $ipParts[3]
    $inner[7] = ($ClientPort -shr 8); $inner[8] = ($ClientPort -band 0xFF)
    $inner[9] = ($Payload.Length -shr 8); $inner[10] = ($Payload.Length -band 0xFF)
    [Array]::Copy($Payload, 0, $inner, 11, $Payload.Length)

    if (-not $Encrypt) {
        return , $inner
    }

    $blob = Wrap-Data -Key $Key -Plain $inner
    $outer = New-Object byte[] (3 + $blob.Length)
    $outer[0] = 0xC0; $outer[1] = 0xDE; $outer[2] = 0x02
    [Array]::Copy($blob, 0, $outer, 3, $blob.Length)
    return , $outer
}

# --- Основной поток теста ---

# Тест туннеля между Proxy.Server и (эмуляцией) Proxy.Client.
# Запускает Proxy.Server, играет роль реального клиента и роль туннеля прокси-клиента.
# Проверяет: клиент -> сервер -> кадр прокси-клиенту -> ответ серверу -> клиенту.
# Если задан параметр -Key, кадры проверяются на шифрование AES-256-GCM.

$root = Split-Path -Parent $PSScriptRoot
$serverDll = Join-Path $root "Proxy.Server\bin\Release\net8.0\Proxy.Server.dll"

if (-not (Test-Path $serverDll)) {
    throw "Не найдена сборка: $serverDll. Сначала выполните: dotnet build Proxify.slnx -c Release"
}

$listenPort = 27015
$proxyClientPort = 5600

$encrypted = -not [string]::IsNullOrEmpty($Key)
if ($encrypted) {
    $cipherKey = Get-CipherKey $Key
    Write-Host "=== Тест туннеля (с шифрованием AES-256-GCM) ==="
} else {
    Write-Host "=== Тест туннеля (без шифрования) ==="
}
Write-Host ""

$serverArgs = @($serverDll, "--port", "$listenPort", "--client", "127.0.0.1:$proxyClientPort")
if ($encrypted) { $serverArgs += @("--key", $Key) }

$proc = Start-Process dotnet -ArgumentList $serverArgs -PassThru -NoNewWindow
Start-Sleep -Milliseconds 1500

$tunnel = New-Object System.Net.Sockets.UdpClient($proxyClientPort)
$client = New-Object System.Net.Sockets.UdpClient
$client.Connect("127.0.0.1", $listenPort)

try {
    # 1. Реальный клиент отправляет пакет на прокси-сервер
    $payload = [Text.Encoding]::UTF8.GetBytes("HELLO")
    [void]$client.Send($payload, $payload.Length)
    Write-Host "[1] Клиент отправил 'HELLO' на 127.0.0.1:$listenPort"

    # 2. Прокси-сервер должен доставить кадр на туннель (порт 5600)
    $tunnel.Client.ReceiveTimeout = 3000
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $frame = $tunnel.Receive([ref]$ep)

    $decoded = Decode-OuterFrame -Frame $frame -Key $cipherKey -ExpectEncrypted $encrypted
    Write-Host "[2] Кадр от сервера: клиент=$($decoded.ClientIp):$($decoded.ClientPort) payload='$($decoded.PayloadText)' $($decoded.WasEncrypted)"

    if ($decoded.PayloadText -ne "HELLO") {
        throw "Кадр не соответствует ожидаемому формату"
    }
    Write-Host "    OK: кадр закодирован верно, настоящий адрес клиента сохранён."

    # 3. Эмулируем прокси-клиента: отвечаем кадром обратно на прокси-сервер
    $reply = [Text.Encoding]::UTF8.GetBytes("REPLY")
    $rf = Build-OuterFrame -ClientIp $decoded.ClientIp -ClientPort $decoded.ClientPort -Payload $reply -Key $cipherKey -Encrypt $encrypted
    [void]$tunnel.Send($rf, $rf.Length, "127.0.0.1", $listenPort)
    Write-Host "[3] Эмуляция прокси-клиента отправила кадр-ответ на 127.0.0.1:$listenPort"

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

    Write-Host ""
    Write-Host "ИТОГ: туннель между прокси-сервером и прокси-клиентом работает."
}
catch {
    Write-Host ""
    Write-Host "ОШИБКА: $($_.Exception.Message)"
    Write-Host "Смотрите лог процесса прокси-сервера выше."
}
finally {
    $tunnel.Close()
    $client.Close()
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
