param(
    [string]$Version = "latest"
)

$Repo = "ParvLab/CryptoTrace"

Write-Host "→ CryptoTrace Installer (Windows)"
Write-Host "  Repo: $Repo"
Write-Host "  Version: $Version"
Write-Host ""

if ($Version -eq "latest") {
    $ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
} else {
    $ApiUrl = "https://api.github.com/repos/$Repo/releases/tags/$Version"
}

Write-Host "→ Fetching release info..."
try {
    $ReleaseJson = Invoke-RestMethod -Uri $ApiUrl
} catch {
    Write-Error "Failed to fetch release info: $_"
    exit 1
}

$ReleaseTag = $ReleaseJson.tag_name
Write-Host "  Release: $ReleaseTag"

$Target = "x86_64-pc-windows-msvc"
$ArchiveName = "cryptotrace-${ReleaseTag}-${Target}.zip"

$AssetUrl = $ReleaseJson.assets | Where-Object { $_.name -eq $ArchiveName } | Select-Object -ExpandProperty browser_download_url

if (-not $AssetUrl) {
    Write-Error "Could not find asset: $ArchiveName"
    exit 1
}

Write-Host "→ Downloading $ArchiveName ..."
$TmpDir = Join-Path $env:TEMP "cryptotrace-install"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

$ZipPath = Join-Path $TmpDir "archive.zip"
try {
    Invoke-WebRequest -Uri $AssetUrl -OutFile $ZipPath
} catch {
    Write-Error "Download failed: $_"
    Remove-Item -Recurse -Force $TmpDir
    exit 1
}

Write-Host "→ Extracting..."
Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force

# Find the extracted directory
$ExtractedDir = Get-ChildItem -Path $TmpDir -Directory | Select-Object -First 1 -ExpandProperty FullName

# Install to LocalAppData
$InstallDir = Join-Path $env:LOCALAPPDATA "cryptotrace"
$BinDir = Join-Path $InstallDir "bin"
$DataDir = Join-Path $InstallDir "share"

Write-Host "→ Installing to $BinDir"
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
Copy-Item (Join-Path $ExtractedDir "cryptotrace.exe") $BinDir
Copy-Item (Join-Path $ExtractedDir "cryptotrace-worker.exe") $BinDir

Write-Host "→ Installing data to $DataDir"
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
if (Test-Path (Join-Path $ExtractedDir "signatures")) {
    Copy-Item -Recurse -Force (Join-Path $ExtractedDir "signatures") $DataDir
}
if (Test-Path (Join-Path $ExtractedDir "calibration_data")) {
    Copy-Item -Recurse -Force (Join-Path $ExtractedDir "calibration_data") $DataDir
}

# Add to PATH for current user
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$BinDir", "User")
    Write-Host "→ Added $BinDir to your PATH (user-level)"
}

# Refresh PATH in the current session so 'cryptotrace' works immediately
$env:Path = "$BinDir;$env:Path"

# Add to PowerShell profile so new terminals also have it
$profileLine = "`$env:Path = '$BinDir;' + `$env:Path"
$profileDir = Split-Path $PROFILE -Parent
if ($profileDir) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    if (!(Test-Path $PROFILE) -or !(Select-String -Path $PROFILE -Pattern [regex]::Escape($BinDir) -Quiet)) {
        Add-Content -Path $PROFILE -Value "`n# Added by CryptoTrace installer`n$profileLine"
    }
}

Write-Host ""
Write-Host "✓ CryptoTrace $ReleaseTag installed!"
Write-Host "  Binary:   $BinDir\cryptotrace.exe"
Write-Host "  Data:     $DataDir"
Write-Host ""
Write-Host "  Run: cryptotrace --help"
Write-Host "  Run: cryptotrace analyze ""your-input"""
Write-Host ""
Write-Host "  → If 'cryptotrace' is not recognized, paste this:"
Write-Host "    `$env:Path = '$BinDir;' + `$env:Path"
