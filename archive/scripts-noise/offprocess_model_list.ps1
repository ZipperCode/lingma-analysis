param(
    [Parameter(Mandatory = $true)]
    [string]$Info,

    [Parameter(Mandatory = $true)]
    [string]$Key,

    [Parameter(Mandatory = $true)]
    [string]$User,

    [Parameter(Mandatory = $true)]
    [string]$MachineId,

    [string]$Endpoint = 'https://lingma.alibabacloud.com/algo/api/v2/model/list',
    [string]$CosyVersion = '2.11.1',
    [string]$IdeVersion = '',
    [string]$DataPolicy = 'DISAGREE',
    [string]$RequestId = ([guid]::NewGuid().ToString()),
    [string]$Slot4 = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NormalizedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path.StartsWith('/algo/')) {
        return $Path.Substring(5)
    }
    return $Path
}

$uri = [Uri]$Endpoint
$normalizedPath = Get-NormalizedPath -Path $uri.AbsolutePath
$date = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()

$payloadObject = [ordered]@{
    cosyVersion = $CosyVersion
    ideVersion  = $IdeVersion
    info        = $Info
    requestId   = $RequestId
    version     = 'v1'
}

$payloadJson = $payloadObject | ConvertTo-Json -Compress
$payload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
$preimage = @($payload, $Key, $date, $Slot4, $normalizedPath) -join "`n"
$md5 = [System.Security.Cryptography.MD5]::Create()
$signatureBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($preimage))
$signature = -join ($signatureBytes | ForEach-Object { $_.ToString('x2') })

$headers = @{
    'Authorization'         = "Bearer COSY.$payload.$signature"
    'Appcode'               = 'cosy'
    'Accept'                = 'application/json'
    'Content-Type'          = 'application/json'
    'Cosy-ClientIp'         = '198.18.0.1'
    'Cosy-ClientType'       = '2'
    'Cosy-Data-Policy'      = $DataPolicy
    'Cosy-Date'             = $date
    'Cosy-Key'              = $Key
    'Cosy-MachineId'        = $MachineId
    'Cosy-MachineOS'        = 'x86_64_windows'
    'Cosy-MachineToken'     = ''
    'Cosy-MachineType'      = ''
    'Cosy-Organization-Id'  = ''
    'Cosy-Organization-Tags'= ''
    'Cosy-User'             = $User
    'Cosy-Version'          = $CosyVersion
    'Login-Version'         = 'v2'
}

try {
    $handler = New-Object System.Net.Http.HttpClientHandler
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $Endpoint)

    foreach ($entry in $headers.GetEnumerator()) {
        [void]$request.Headers.TryAddWithoutValidation($entry.Key, $entry.Value)
    }

    $response = $client.SendAsync($request).GetAwaiter().GetResult()
    $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

    [pscustomobject]@{
        endpoint       = $Endpoint
        normalizedPath = $normalizedPath
        requestId      = $RequestId
        cosyDate       = $date
        signature      = $signature
        status         = [int]$response.StatusCode
        body           = $body
    } | ConvertTo-Json -Depth 8
} catch {
    [pscustomobject]@{
        endpoint       = $Endpoint
        normalizedPath = $normalizedPath
        requestId      = $RequestId
        cosyDate       = $date
        signature      = $signature
        errorType      = $_.Exception.GetType().FullName
        errorMessage   = $_.Exception.Message
    } | ConvertTo-Json -Depth 8
    exit 1
} finally {
    if ($null -ne $request) {
        $request.Dispose()
    }
    if ($null -ne $client) {
        $client.Dispose()
    }
    if ($null -ne $handler) {
        $handler.Dispose()
    }
}
