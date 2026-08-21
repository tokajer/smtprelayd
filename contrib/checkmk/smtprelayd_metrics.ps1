#Requires -Version 5.0
<#
Checkmk local check for smtprelayd's /metrics endpoint, Windows agent.

Install:
  Copy to C:\ProgramData\checkmk\agent\local\smtprelayd_metrics.ps1
then run service discovery on the host in Checkmk. The Windows agent runs
.ps1 files in that directory automatically; no extra registration needed
on a current agent.

Configuration is via the variables below, or by setting the equivalent
environment variables (same names as the Linux plugin) before the agent
runs this script, e.g. via a machine environment variable.

See docs/CHECKMK.md in the smtprelayd repository for the full guide.
#>

# Reads an environment variable as a double, falling back to $Default when
# unset or empty. Deliberately not "if (-not $value)": 0 is a legitimate
# threshold and is falsy in PowerShell, which would otherwise silently
# discard an operator's explicit "alert on anything" setting.
function Get-EnvDouble([string]$Name, [double]$Default) {
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrEmpty($v)) { return $Default }
    return [double]$v
}

$Url                 = $env:SMTPRELAYD_METRICS_URL;      if (-not $Url) { $Url = 'http://127.0.0.1:9025/metrics' }
$Token               = $env:SMTPRELAYD_METRICS_TOKEN
$QueueWarn           = Get-EnvDouble 'SMTPRELAYD_QUEUE_WARN' 200
$QueueCrit           = Get-EnvDouble 'SMTPRELAYD_QUEUE_CRIT' 1000
$DeferredWarn        = Get-EnvDouble 'SMTPRELAYD_DEFERRED_WARN' 50
$DeferredCrit        = Get-EnvDouble 'SMTPRELAYD_DEFERRED_CRIT' 200
$BounceWarn          = Get-EnvDouble 'SMTPRELAYD_BOUNCE_WARN' 1
$BounceCrit          = Get-EnvDouble 'SMTPRELAYD_BOUNCE_CRIT' 5
$AuthFailWarn        = Get-EnvDouble 'SMTPRELAYD_AUTHFAIL_WARN' 1
$AuthFailCrit        = Get-EnvDouble 'SMTPRELAYD_AUTHFAIL_CRIT' 3
$TokenAgeWarn        = Get-EnvDouble 'SMTPRELAYD_TOKEN_AGE_WARN' 3300
$TokenAgeCrit        = Get-EnvDouble 'SMTPRELAYD_TOKEN_AGE_CRIT' 3600
$ApiAuthFailWarn     = Get-EnvDouble 'SMTPRELAYD_API_AUTHFAIL_WARN' 1
$ApiAuthFailCrit     = Get-EnvDouble 'SMTPRELAYD_API_AUTHFAIL_CRIT' 5
$NotifyFailWarn      = Get-EnvDouble 'SMTPRELAYD_NOTIFYFAIL_WARN' 1
$NotifyFailCrit      = Get-EnvDouble 'SMTPRELAYD_NOTIFYFAIL_CRIT' 3

$StateDir  = $env:SMTPRELAYD_STATE_DIR; if (-not $StateDir) { $StateDir = 'C:\ProgramData\checkmk\agent\state' }
$StateFile = Join-Path $StateDir 'smtprelayd_metrics.json'
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

function Write-Service([int]$State, [string]$Name, [string]$Perf, [string]$Text) {
    $Name = $Name -replace ' ', '_'
    if (-not $Perf) { $Perf = '-' }
    Write-Output "$State $Name $Perf $Text"
}

function State-For([double]$Val, [double]$Warn, [double]$Crit) {
    if ($Val -ge $Crit) { return 2 }
    if ($Val -ge $Warn) { return 1 }
    return 0
}

$headers = @{}
if ($Token) { $headers['Authorization'] = "Bearer $Token" }

try {
    $raw = Invoke-WebRequest -Uri $Url -Headers $headers -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    $body = $raw.Content
} catch {
    Write-Service 2 'smtprelayd_metrics' '-' "could not reach $Url"
    return
}

Write-Service 0 'smtprelayd_metrics' '-' "reachable ($Url)"

$prev = @{}
if (Test-Path $StateFile) {
    try { (Get-Content $StateFile -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $prev[$_.Name] = [double]$_.Value } } catch { }
}

$queued = @{}; $deferredq = @{}; $delivered = @{}; $bounced = @{}; $deferredTotal = @{}
$authFail = @{}; $tokenAge = @{}; $hasToken = @{}; $lastDelivery = @{}; $rate = @{}
$routes = New-Object System.Collections.ArrayList
$apiAuthFail = 0.0
$notifyFail = 0.0

$lineRe = '^(?<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(\{(?<labels>[^}]*)\})?\s+(?<value>[0-9eE+\-.]+)\s*$'

foreach ($line in ($body -split "`n")) {
    $line = $line.TrimEnd("`r")
    if (-not $line -or $line.StartsWith('#')) { continue }
    $m = [regex]::Match($line, $lineRe)
    if (-not $m.Success) { continue }
    $name = $m.Groups['name'].Value
    $value = [double]$m.Groups['value'].Value
    $route = ''
    $lblState = ''
    if ($m.Groups['labels'].Success) {
        foreach ($pair in ($m.Groups['labels'].Value -split ',')) {
            $kv = $pair -split '=', 2
            if ($kv.Length -ne 2) { continue }
            $k = $kv[0]
            $v = $kv[1].Trim('"')
            if ($k -eq 'route') { $route = $v }
            if ($k -eq 'state') { $lblState = $v }
        }
    }
    if ($route -and -not $routes.Contains($route)) { [void]$routes.Add($route) }

    switch ($name) {
        'smtprelayd_queue_size'                { if ($lblState -eq 'queued') { $queued[$route] = $value } else { $deferredq[$route] = $value } }
        'smtprelayd_delivered_total'           { $delivered[$route] = $value }
        'smtprelayd_bounced_total'              { $bounced[$route] = $value }
        'smtprelayd_deferred_total'             { $deferredTotal[$route] = $value }
        'smtprelayd_auth_failures_total'        { $authFail[$route] = $value }
        'smtprelayd_oauth_token_age_seconds'    { $tokenAge[$route] = $value; $hasToken[$route] = $true }
        'smtprelayd_last_delivery_time'         { $lastDelivery[$route] = $value }
        'smtprelayd_delivery_rate_per_minute'   { $rate[$route] = $value }
        'smtprelayd_api_auth_failures_total'    { $apiAuthFail = $value }
        'smtprelayd_notification_failures_total'{ $notifyFail = $value }
    }
}

$newState = @{}
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

foreach ($route in $routes) {
    $q = [double]($queued[$route]); $dq = [double]($deferredq[$route])
    $qState = [Math]::Max((State-For $q $QueueWarn $QueueCrit), (State-For $dq $DeferredWarn $DeferredCrit))
    Write-Service $qState "SMTP_Queue_$route" "queued=$q;$QueueWarn;$QueueCrit|deferred=$dq;$DeferredWarn;$DeferredCrit" "$q queued, $dq deferred"

    $d = [double]($delivered[$route]); $b = [double]($bounced[$route]); $dt = [double]($deferredTotal[$route]); $rt = [double]($rate[$route])
    $bKey = "bounced:$route"
    $bPrev = if ($prev.ContainsKey($bKey)) { $prev[$bKey] } else { $b }
    $bDelta = $b - $bPrev
    if ($bDelta -lt 0) { $bDelta = $b }
    Write-Service (State-For $bDelta $BounceWarn $BounceCrit) "SMTP_Delivery_$route" "delivered=${d}c|bounced=${b}c|deferred_total=${dt}c|rate_per_min=$rt" "$bDelta new bounce(s) since last check, $rt msg/min, $d delivered total"
    $newState[$bKey] = $b

    $af = [double]($authFail[$route])
    $afKey = "authfail:$route"
    $afPrev = if ($prev.ContainsKey($afKey)) { $prev[$afKey] } else { $af }
    $afDelta = $af - $afPrev
    if ($afDelta -lt 0) { $afDelta = $af }
    $aState = State-For $afDelta $AuthFailWarn $AuthFailCrit
    if ($hasToken.ContainsKey($route)) {
        $age = [double]($tokenAge[$route])
        $aState = [Math]::Max($aState, (State-For $age $TokenAgeWarn $TokenAgeCrit))
        Write-Service $aState "SMTP_Auth_$route" "auth_failures=${af}c|token_age=${age}s;$TokenAgeWarn;$TokenAgeCrit" "$afDelta new auth failure(s) since last check, token age ${age}s"
    } else {
        Write-Service $aState "SMTP_Auth_$route" "auth_failures=${af}c" "$afDelta new auth failure(s) since last check, no OAuth2 token cached (non-XOAUTH2 route or none issued yet)"
    }
    $newState[$afKey] = $af

    if ($lastDelivery.ContainsKey($route)) {
        $age = $now - [double]($lastDelivery[$route])
        Write-Service 0 "SMTP_Last_Delivery_$route" "age=${age}s" "$age s since the last successful delivery"
    }
}

$aafPrev = if ($prev.ContainsKey('api_auth_failures')) { $prev['api_auth_failures'] } else { $apiAuthFail }
$aafDelta = $apiAuthFail - $aafPrev
if ($aafDelta -lt 0) { $aafDelta = $apiAuthFail }
Write-Service (State-For $aafDelta $ApiAuthFailWarn $ApiAuthFailCrit) 'SMTP_API_Auth_Failures' "api_auth_failures=${apiAuthFail}c" "$aafDelta new rejected bearer token(s) since last check"
$newState['api_auth_failures'] = $apiAuthFail

$nfPrev = if ($prev.ContainsKey('notification_failures')) { $prev['notification_failures'] } else { $notifyFail }
$nfDelta = $notifyFail - $nfPrev
if ($nfDelta -lt 0) { $nfDelta = $notifyFail }
Write-Service (State-For $nfDelta $NotifyFailWarn $NotifyFailCrit) 'SMTP_Notification_Failures' "notification_failures=${notifyFail}c" "$nfDelta new bounce-digest delivery failure(s) since last check"
$newState['notification_failures'] = $notifyFail

$newState | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8
