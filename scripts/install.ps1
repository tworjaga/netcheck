# Installs netcheck on Windows:
#
#   irm https://raw.githubusercontent.com/tworjaga/netcheck/main/scripts/install.ps1 | iex
#
# It downloads the binary for this PC from the latest release, checks it
# against the release's SHA256SUMS, then runs "netcheck install", which
# copies it to %LOCALAPPDATA%\Programs\netcheck and adds that to your PATH.
# Settings, all optional:
#   $env:NETCHECK_VERSION   a release tag, e.g. v0.9.0 (default: the latest)
#   $env:NETCHECK_DOWNLOAD  where the release files are (a mirror)

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $repo = 'tworjaga/netcheck'

    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $asset = "netcheck-windows-$arch.exe"
    if ($env:NETCHECK_DOWNLOAD) {
        $base = $env:NETCHECK_DOWNLOAD
    } elseif ($env:NETCHECK_VERSION) {
        $base = "https://github.com/$repo/releases/download/$env:NETCHECK_VERSION"
    } else {
        $base = "https://github.com/$repo/releases/latest/download"
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("netcheck-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $tmp | Out-Null
    try {
        Write-Host "  Downloading $asset..."
        $exe = Join-Path $tmp 'netcheck.exe'
        Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile $exe
        $sums = (Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS").Content
        if ($sums -is [byte[]]) { $sums = [Text.Encoding]::UTF8.GetString($sums) }

        $want = $null
        foreach ($line in $sums -split "`n") {
            $f = $line.Trim() -split '\s+'
            if ($f.Count -eq 2 -and $f[1].TrimStart('*') -eq $asset) { $want = $f[0] }
        }
        if (-not $want) { throw "SHA256SUMS doesn't list $asset" }
        $got = (Get-FileHash -Algorithm SHA256 $exe).Hash
        if ($got -ne $want.ToUpper()) { throw "the download doesn't match SHA256SUMS; nothing was installed" }
        Write-Host '  Checked against SHA256SUMS.'

        & $exe install --yes
        if ($LASTEXITCODE -ne 0) { throw "netcheck install failed (exit $LASTEXITCODE)" }
    } catch {
        Write-Host "  netcheck install: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}
