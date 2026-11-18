param(
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$HostProperties = (Join-Path $PSScriptRoot '../../../../Banca-Movil-Android/local.properties')
)
$ErrorActionPreference = 'Stop'
if (!$JavaHome -or !(Test-Path -LiteralPath (Join-Path $JavaHome 'bin/java.exe'))) { throw 'Set JAVA_HOME to a JDK 25 directory' }
$entry = Get-Content -LiteralPath $HostProperties | Where-Object { $_ -match '^encryptConfig\.password\.dev\s*=' } | Select-Object -Last 1
if (!$entry) { throw 'Missing private dev bootstrap password' }
$privatePassword = ($entry -split '=', 2)[1].Trim().Replace('\=', '=')
try { $bytes = [Convert]::FromBase64String($privatePassword); [Array]::Clear($bytes, 0, $bytes.Length) }
catch { throw 'Invalid private dev password format' }
$previousJava = $env:JAVA_HOME
$previousOptions = $env:JDK_JAVA_OPTIONS
$previousPassword = $env:PLAY_INTEGRITY_PASSWORD_BASE64
try {
    $env:JAVA_HOME = $JavaHome
    $socketDirectory = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.gradle'
    $env:JDK_JAVA_OPTIONS = "$previousOptions -Djdk.net.unixdomain.tmpdir=$socketDirectory"
    $env:PLAY_INTEGRITY_PASSWORD_BASE64 = $privatePassword
    Push-Location (Split-Path $PSScriptRoot -Parent)
    try { & './mvnw.cmd' -Plocal-simulation spring-boot:run '-Dspring-boot.run.profiles=local-simulation' }
    finally { Pop-Location }
} finally {
    $env:JAVA_HOME = $previousJava
    $env:JDK_JAVA_OPTIONS = $previousOptions
    $env:PLAY_INTEGRITY_PASSWORD_BASE64 = $previousPassword
    $privatePassword = $null
}
