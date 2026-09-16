<#
.SYNOPSIS
    Opens a TLS connection to an smtprelayd listener and reports what was
    negotiated.

.DESCRIPTION
    Connects with TLS 1.2 by default, which is what the listener requires
    unless min_tls says otherwise. Use -Protocol to force a different version,
    or -ProbeAll to try every version in turn when a device reports
    "unsupported TLS version" and it is not yet clear which side refused.

    The negotiated key exchange is printed because it is the setting that most
    often blocks a legacy device: Go disabled RSA key exchange by default in
    1.22, so a client that cannot do ECDHE fails even when the TLS version
    matches.

    Run it from the machine the device connects from where possible. Windows
    disables TLS versions client-side in SCHANNEL, and such a failure looks
    identical to the relay refusing.

.PARAMETER RelayHost
    Host or address of the relay.

.PARAMETER Port
    465 for implicit TLS; 587 or 25 together with -StartTls.

.PARAMETER CertName
    Name sent as SNI and checked against the certificate. Must be one of its
    subject alternative names. Defaults to RelayHost.

.PARAMETER StartTls
    Negotiate STARTTLS on a plaintext port instead of connecting with TLS
    immediately.

.PARAMETER Protocol
    TLS version to use. Default Tls12.

.PARAMETER ProbeAll
    Try every TLS version instead of only -Protocol.

.EXAMPLE
    .\Test-SmtpTls.ps1 -RelayHost relay.intern.example.at -Port 465

.EXAMPLE
    .\Test-SmtpTls.ps1 -RelayHost relay.intern.example.at -Port 587 -StartTls

.EXAMPLE
    .\Test-SmtpTls.ps1 -RelayHost relay.intern.example.at -Port 465 -ProbeAll
#>
[CmdletBinding()]
param(
    [string]$RelayHost = '127.0.0.1',
    [int]$Port = 465,
    [string]$CertName = '',
    [switch]$StartTls,
    [ValidateSet('Tls', 'Tls11', 'Tls12', 'Tls13')]
    [string]$Protocol = 'Tls12',
    [switch]$ProbeAll
)

if (-not $CertName) { $CertName = $RelayHost }

# Accept any certificate: this reports what is served, it does not judge it.
# Trust is evaluated separately at the end.
$acceptAll = [System.Net.Security.RemoteCertificateValidationCallback] { $true }

$script:lastCert = $null

# innerMost unwraps the exception chain. The useful TLS message is usually
# two levels down, and the outer one only ever says "authentication failed".
function Get-InnerMostMessage($ex) {
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

function Enter-StartTls($stream) {
    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
    $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::ASCII)
    $writer.NewLine = "`r`n"
    $writer.AutoFlush = $true

    $banner = $reader.ReadLine()
    Write-Verbose "S: $banner"
    if ($banner -notmatch '^220') { throw "unerwarteter Banner: $banner" }

    $writer.WriteLine('EHLO tls-probe.invalid')
    $offersStartTls = $false
    do {
        $line = $reader.ReadLine()
        Write-Verbose "S: $line"
        if ($line -match 'STARTTLS') { $offersStartTls = $true }
    } while ($line -match '^250-')
    if (-not $offersStartTls) { throw 'der Listener bietet kein STARTTLS an' }

    $writer.WriteLine('STARTTLS')
    $ready = $reader.ReadLine()
    Write-Verbose "S: $ready"
    if ($ready -notmatch '^220') { throw "STARTTLS abgelehnt: $ready" }
}

function Test-TlsVersion($protoName, $label) {
    # A .NET without this value (TLS 1.3 before .NET Framework 4.8) throws
    # here rather than returning $null.
    try {
        $proto = [System.Security.Authentication.SslProtocols]::$protoName
    } catch {
        return New-Object psobject -Property ([ordered]@{
            Version = $label; Ergebnis = 'N/A'; Ausgehandelt = ''
            Cipher = ''; KeyExchange = ''
            Detail = 'von diesem .NET nicht unterstuetzt'
        })
    }

    $tcp = $null
    $ergebnis = 'ABGELEHNT'
    $ausgehandelt = ''
    $cipher = ''
    $kx = ''
    $detail = ''
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($RelayHost, $Port)
        $stream = $tcp.GetStream()

        if ($StartTls) { Enter-StartTls $stream }

        $ssl = New-Object System.Net.Security.SslStream($stream, $false, $acceptAll)
        $ssl.AuthenticateAsClient($CertName, $null, $proto, $false)

        $ergebnis = 'OK'
        $ausgehandelt = [string]$ssl.SslProtocol
        $cipher = '{0} {1} Bit' -f $ssl.CipherAlgorithm, $ssl.CipherStrength
        $kx = [string]$ssl.KeyExchangeAlgorithm
        # 44550 is SCHANNEL's ECDH_Ephem, unnamed in the .NET Framework enum.
        if ($kx -eq '44550') { $kx = 'ECDH_Ephem' }
        $script:lastCert = $ssl.RemoteCertificate
        $ssl.Dispose()
    } catch {
        $detail = Get-InnerMostMessage $_.Exception
    } finally {
        if ($tcp) { $tcp.Close() }
    }

    New-Object psobject -Property ([ordered]@{
        Version = $label; Ergebnis = $ergebnis; Ausgehandelt = $ausgehandelt
        Cipher = $cipher; KeyExchange = $kx; Detail = $detail
    })
}

$versions = [ordered]@{ 'Tls' = 'TLS 1.0'; 'Tls11' = 'TLS 1.1'; 'Tls12' = 'TLS 1.2'; 'Tls13' = 'TLS 1.3' }

if ($StartTls) { $mode = 'STARTTLS' } else { $mode = 'implizites TLS' }
Write-Host ("Pruefe {0}:{1} ({2}), Zertifikatsname '{3}'" -f $RelayHost, $Port, $mode, $CertName) -ForegroundColor Cyan
Write-Host ''

if ($ProbeAll) {
    $results = foreach ($name in $versions.Keys) { Test-TlsVersion $name $versions[$name] }
} else {
    $results = Test-TlsVersion $Protocol $versions[$Protocol]
}

$results | Format-Table Version, Ergebnis, Ausgehandelt, Cipher, KeyExchange -AutoSize
foreach ($r in $results) {
    if ($r.Detail) { Write-Host ('  {0}: {1}' -f $r.Version, $r.Detail) -ForegroundColor DarkGray }
}

if ($script:lastCert) {
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($script:lastCert)
    $tage = [int]($c.NotAfter - (Get-Date)).TotalDays
    Write-Host ''
    Write-Host 'Zertifikat, das der Listener ausliefert:' -ForegroundColor Cyan
    Write-Host ('  Subject   : {0}' -f $c.Subject)
    Write-Host ('  Aussteller: {0}' -f $c.Issuer)
    Write-Host ('  Gueltig bis: {0}  ({1} Tage)' -f $c.NotAfter, $tage)
    $san = $c.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
    if ($san) { Write-Host ('  SANs      : {0}' -f $san.Format($false)) }

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    if ($chain.Build($c)) {
        Write-Host '  Vertrauen : OK, dieser Rechner vertraut dem Zertifikat' -ForegroundColor Green
    } else {
        Write-Host '  Vertrauen : NICHT vertraut auf diesem Rechner' -ForegroundColor Yellow
        Write-Host '              Bei einem selbstsignierten Zertifikat erwartet. Importieren mit:'
        Write-Host '              Import-Certificate -FilePath <relay.crt> -CertStoreLocation Cert:\LocalMachine\Root'
    }
} else {
    Write-Host ''
    Write-Host 'Kein Zertifikat erhalten - es kam keine TLS-Verbindung zustande.' -ForegroundColor Yellow
}
