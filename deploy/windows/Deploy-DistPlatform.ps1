<#
.SYNOPSIS
    Interactive deployment of the dist-platform Compose stack on Windows.

.DESCRIPTION
    Runs the deployment described in docs/diagrams/production-deployment.drawio
    and deploy/compose/README.md, asking for what it cannot safely decide and
    deciding what it can.

    Every phase is idempotent. Re-running after a failure picks up where it
    stopped: an existing .env is repaired rather than replaced, an existing
    keystore is never overwritten, an already-seeded volume is left alone.

    What it deliberately does NOT do:

    - Generate root keys unattended in production. The ceremony is a human act
      and the script's job is to get you to it with everything else in place.
    - Put a password in argv or in the environment. Both are readable by other
      processes on the machine; passwords reach the ceremony over stdin only.
    - Leave offline.kdbx on this host. It prompts for removable media and
      verifies the move, because a root keystore on a networked machine
      defeats the split it exists to create (PLAN.md 3.3).
    - Terminate TLS. Both published ports stay on loopback; putting a
      terminator in front is a separate, deliberate act.

.PARAMETER Mode
    Production (default) or Dev. Dev passes --dev to the ceremony: one
    operator, a known password, all five root keys in one place. Never ship a
    Dev keyset.

.PARAMETER SkipCeremony
    Use keystores and a repository that already exist. The normal choice when
    redeploying, or when the ceremony happened on a different machine.

.PARAMETER Force
    Permit destructive steps that are otherwise refused: overwriting .env,
    re-seeding a populated volume.

.PARAMETER AllowOfflineKeyOnHost
    Skip the offline-media move. For a Dev keyset or a throwaway host. Using
    this in production is the finding that was already flagged against this
    repository once.

.EXAMPLE
    pwsh -File deploy\windows\Deploy-DistPlatform.ps1

.EXAMPLE
    pwsh -File deploy\windows\Deploy-DistPlatform.ps1 -Mode Dev -AllowOfflineKeyOnHost
#>

# Below the help block, not above it. A `#Requires` statement preceding
# comment-based help suppresses the whole block: Get-Help then returns
# generated syntax and reports "no parameter matches criteria" for flags that
# are plainly documented in the file. It still takes effect down here.
#Requires -Version 7.0

[CmdletBinding()]
param(
    [ValidateSet('Production', 'Dev')]
    [string]$Mode = 'Production',
    [switch]$SkipCeremony,
    [switch]$Force,
    [switch]$AllowOfflineKeyOnHost
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --------------------------------------------------------------------------
# Paths. Everything is derived from the script's own location so the working
# directory does not matter.
# --------------------------------------------------------------------------
$RepoRoot    = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$ComposeDir  = Join-Path $RepoRoot 'deploy\compose'
$EnvFile     = Join-Path $ComposeDir '.env'
$EnvExample  = Join-Path $ComposeDir '.env.example'
$SecretsDir  = Join-Path $ComposeDir 'secrets'
$SecretsFile = Join-Path $ComposeDir 'docker-compose.secrets.yml'
$Project     = 'dist-platform'

$script:Warnings = @()

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
function Write-Step([string]$Text) {
    Write-Host ''
    Write-Host "── $Text " -NoNewline -ForegroundColor Cyan
    Write-Host ('─' * [Math]::Max(0, 74 - $Text.Length)) -ForegroundColor DarkCyan
}
function Write-Ok   ([string]$T) { Write-Host "   [ ok ] $T" -ForegroundColor Green }
function Write-Info ([string]$T) { Write-Host "   [ .. ] $T" -ForegroundColor Gray }
function Write-Warn ([string]$T) {
    Write-Host "   [warn] $T" -ForegroundColor Yellow
    $script:Warnings += $T
}
function Write-Fail ([string]$T) { Write-Host "   [fail] $T" -ForegroundColor Red }

function Confirm-Step([string]$Question, [bool]$Default = $true) {
    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    while ($true) {
        $answer = (Read-Host "   $Question [$hint]").Trim().ToLowerInvariant()
        if ($answer -eq '')                { return $Default }
        if ($answer -in @('y', 'yes'))     { return $true }
        if ($answer -in @('n', 'no'))      { return $false }
    }
}

function Read-Secret([string]$Prompt, [switch]$Confirm) {
    # SecureString for the prompt so it is not echoed. It is converted to
    # plaintext only at the moment of use and the plaintext is not returned to
    # a variable that outlives the call site any longer than necessary --
    # PowerShell offers no better guarantee than that, which is worth knowing
    # rather than pretending otherwise.
    while ($true) {
        $first = Read-Host "   $Prompt" -AsSecureString
        $a = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
             [Runtime.InteropServices.Marshal]::SecureStringToBSTR($first))
        if ([string]::IsNullOrWhiteSpace($a)) { Write-Fail 'Empty. Try again.'; continue }
        if (-not $Confirm) { return $a }

        $second = Read-Host "   Repeat" -AsSecureString
        $b = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
             [Runtime.InteropServices.Marshal]::SecureStringToBSTR($second))
        if ($a -ceq $b) { return $a }
        Write-Fail 'They did not match. Try again.'
    }
}

function New-StrongPassword([int]$Bytes = 24) {
    # URL-safe base64: goes into a .env value and a Postgres connection string
    # without quoting surprises.
    $raw = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($raw)
    [Convert]::ToBase64String($raw).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Protect-File([string]$Path) {
    # Current user and SYSTEM only. Inheritance off, so a permissive parent
    # directory does not re-admit Users.
    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
    foreach ($id in @([Security.Principal.WindowsIdentity]::GetCurrent().Name, 'NT AUTHORITY\SYSTEM')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $id, 'FullControl', 'Allow'))
    }
    Set-Acl -Path $Path -AclObject $acl
}

# --------------------------------------------------------------------------
# Compose / Docker helpers
# --------------------------------------------------------------------------
function Get-ComposeArgs {
    $composeArgs = @('compose', '-p', $Project, '-f', (Join-Path $ComposeDir 'docker-compose.yml'))
    if (Test-Path $SecretsFile) { $composeArgs += @('-f', $SecretsFile) }
    return $composeArgs
}

function Invoke-Compose {
    param([Parameter(ValueFromRemainingArguments)] [string[]]$Arguments)
    $all = (Get-ComposeArgs) + $Arguments
    Write-Verbose "docker $($all -join ' ')"
    & docker @all
    if ($LASTEXITCODE -ne 0) { throw "docker compose $($Arguments -join ' ') failed ($LASTEXITCODE)" }
}

function Test-DockerVolume([string]$Name) {
    $null = & docker volume inspect $Name 2>$null
    return $LASTEXITCODE -eq 0
}

function Test-VolumeEmpty([string]$Name) {
    $out = & docker run --rm -v "${Name}:/v" alpine:3 sh -c 'ls -A /v 2>/dev/null | head -1'
    return [string]::IsNullOrWhiteSpace($out)
}

function Copy-IntoVolume {
    <#
      Seeds a named volume from a host directory and fixes ownership.

      The chown matters and is easy to miss: the signer runs as uid 10001 and
      mounts tuf-metadata read-write. Seed it as root and the container starts,
      passes its healthcheck, and fails on the first publish with a permission
      error thirty minutes later.
    #>
    param(
        [Parameter(Mandatory)] [string]$Volume,
        [Parameter(Mandatory)] [string]$Source,
        [int]$Uid = 10001
    )
    $src = (Resolve-Path $Source).Path
    & docker run --rm -v "${Volume}:/dst" -v "${src}:/src:ro" alpine:3 `
        sh -c "cp -a /src/. /dst/ && chown -R ${Uid}:${Uid} /dst"
    if ($LASTEXITCODE -ne 0) { throw "seeding volume $Volume from $src failed" }
}

# --------------------------------------------------------------------------
# .env handling
# --------------------------------------------------------------------------
function Read-EnvFile([string]$Path) {
    $map = [ordered]@{}
    if (-not (Test-Path $Path)) { return $map }
    foreach ($line in Get-Content $Path) {
        if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
        $k, $v = $line -split '=', 2
        $map[$k.Trim()] = $v.Trim()
    }
    return $map
}

function Write-EnvFile([string]$Path, $Map) {
    $lines = @(
        '# Generated by deploy\windows\Deploy-DistPlatform.ps1.',
        '# Secrets are referenced by path, not by value, wherever the service',
        '# supports it -- an environment variable is inherited by every child',
        '# process and lands in a crash dump.',
        ''
    )
    foreach ($k in $Map.Keys) { $lines += "$k=$($Map[$k])" }
    Set-Content -Path $Path -Value $lines -Encoding utf8NoBOM
    Protect-File $Path
}

# ==========================================================================
# 1. Preflight
# ==========================================================================
Write-Step 'Preflight'

foreach ($tool in @('docker', 'git')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Fail "$tool is not on PATH."
        exit 1
    }
}
Write-Ok 'docker and git are present'

$null = & docker version --format '{{.Server.Version}}' 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Fail 'The Docker daemon is not reachable. Start Docker Desktop and re-run.'
    exit 1
}
Write-Ok "Docker daemon $(& docker version --format '{{.Server.Version}}')"

$null = & docker compose version 2>$null
if ($LASTEXITCODE -ne 0) { Write-Fail 'Compose v2 is required (docker compose, not docker-compose).'; exit 1 }
Write-Ok 'Compose v2'

$HasUv = [bool](Get-Command uv -ErrorAction SilentlyContinue)
if (-not $HasUv) {
    Write-Warn 'uv is not on PATH. The ceremony and the delegate step need it; the stack itself does not.'
    if (-not $SkipCeremony) {
        Write-Fail 'Install uv (https://docs.astral.sh/uv/) or re-run with -SkipCeremony.'
        exit 1
    }
}
else { Write-Ok "uv $((& uv --version) -replace '^uv\s*','')" }

# ==========================================================================
# 2. Postgres 17 -> 18 migration check
# ==========================================================================
Write-Step 'Postgres volume'

$OldVolume = "${Project}_pgdata"
$NewVolume = "${Project}_postgres-data"

if ((Test-DockerVolume $OldVolume) -and -not (Test-DockerVolume $NewVolume)) {
    Write-Warn "A 17-era volume '$OldVolume' exists and has not been migrated."
    Write-Host ''
    Write-Host '   The stack now runs Postgres 18, whose data directory moved. Bringing it' -ForegroundColor Yellow
    Write-Host '   up will create an EMPTY 18 cluster in a new volume. Nothing errors: the' -ForegroundColor Yellow
    Write-Host '   stack starts, passes its healthcheck, and serves an empty registry.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '   Dump first (deploy\compose\README.md has the full sequence):' -ForegroundColor Yellow
    Write-Host "     docker run --rm -v ${OldVolume}:/var/lib/postgresql/data postgres:17-alpine ``" -ForegroundColor Gray
    Write-Host '       pg_dumpall -U dist > dist-17.sql' -ForegroundColor Gray
    Write-Host ''
    if (-not (Confirm-Step 'Continue and create a fresh empty database?' $false)) {
        Write-Info 'Stopped. The 17 volume is untouched.'
        exit 0
    }
}
elseif (Test-DockerVolume $NewVolume) { Write-Ok "$NewVolume exists" }
else { Write-Ok 'No existing database; one will be created' }

# ==========================================================================
# 3. .env
# ==========================================================================
Write-Step 'Configuration (.env)'

if (-not (Test-Path $EnvExample)) { Write-Fail "Missing $EnvExample"; exit 1 }

$envMap = Read-EnvFile $EnvFile
if ($envMap.Count -gt 0) {
    Write-Info "$EnvFile exists; filling gaps only. -Force rewrites it."
    if ($Force -and (Confirm-Step 'Discard the existing .env and start fresh?' $false)) {
        $envMap = [ordered]@{}
    }
}

# --- POSTGRES_PASSWORD: required; compose refuses to start without it -------
if (-not $envMap['POSTGRES_PASSWORD']) {
    if (Confirm-Step 'Generate a random POSTGRES_PASSWORD?' $true) {
        $envMap['POSTGRES_PASSWORD'] = New-StrongPassword
        Write-Ok 'Generated (32 chars, base64url)'
    }
    else { $envMap['POSTGRES_PASSWORD'] = Read-Secret 'POSTGRES_PASSWORD' -Confirm }
}
else { Write-Ok 'POSTGRES_PASSWORD set' }

# --- ADMIN_BOOTSTRAP_PASSWORD: first start only -----------------------------
if (-not $envMap.Contains('ADMIN_BOOTSTRAP_PASSWORD')) {
    Write-Host '   The bootstrap password creates the `admin` operator on first start and is' -ForegroundColor Gray
    Write-Host '   ignored once any operator exists. Leaving it empty and running' -ForegroundColor Gray
    Write-Host '   `dist_admin.operators add <name>` afterwards keeps it out of a file.' -ForegroundColor Gray
    if (Confirm-Step 'Set a bootstrap password now?' $true) {
        $envMap['ADMIN_BOOTSTRAP_PASSWORD'] = Read-Secret 'ADMIN_BOOTSTRAP_PASSWORD' -Confirm
    }
    else {
        $envMap['ADMIN_BOOTSTRAP_PASSWORD'] = ''
        Write-Info 'Left empty. Create an operator with: docker compose run --rm admin python -m dist_admin.operators add <name>'
    }
}

# --- Binds, ports, cookie ---------------------------------------------------
foreach ($pair in @(
    @{ Key = 'EDGE_BIND';  Default = '127.0.0.1' },
    @{ Key = 'EDGE_PORT';  Default = '8080' },
    @{ Key = 'ADMIN_BIND'; Default = '127.0.0.1' },
    @{ Key = 'ADMIN_PORT'; Default = '8081' },
    @{ Key = 'LOG_LEVEL';  Default = 'INFO' }
)) {
    if (-not $envMap.Contains($pair.Key)) { $envMap[$pair.Key] = $pair.Default }
}

if (-not $envMap.Contains('ADMIN_SECURE_COOKIE')) {
    Write-Host '   Set this to 1 only once a TLS terminator is in front of the admin plane.' -ForegroundColor Gray
    Write-Host '   A Secure cookie is never sent over loopback HTTP, and the symptom is a' -ForegroundColor Gray
    Write-Host '   login form that accepts the password and then returns you to itself.' -ForegroundColor Gray
    $envMap['ADMIN_SECURE_COOKIE'] = if (Confirm-Step 'Is the admin plane behind TLS?' $false) { '1' } else { '0' }
}
if ($envMap['ADMIN_SECURE_COOKIE'] -eq '0' -and $envMap['ADMIN_BIND'] -ne '127.0.0.1') {
    Write-Warn "ADMIN_BIND is $($envMap['ADMIN_BIND']) with ADMIN_SECURE_COOKIE=0: session cookies will cross the network in the clear."
}

# --- SKIP_GATES: a decision, not a default ----------------------------------
if (-not $envMap.Contains('SKIP_GATES')) {
    Write-Host '   Content gates fail closed. With no malware scanner wired up (Phase 3),' -ForegroundColor Gray
    Write-Host '   every artifact is rejected with "gate failed: no malware scanner' -ForegroundColor Gray
    Write-Host '   configured". Naming a gate here records it as skipped, never as passed.' -ForegroundColor Gray
    if (Confirm-Step 'Skip the malware gate for now (ingestion is otherwise inert)?' $false) {
        $envMap['SKIP_GATES'] = 'malware'
        Write-Warn 'SKIP_GATES=malware. Artifacts will be promoted without a malware scan.'
    }
    else { $envMap['SKIP_GATES'] = '' }
}

Write-EnvFile $EnvFile $envMap
Write-Ok "Wrote $EnvFile (ACL: current user + SYSTEM)"

# ==========================================================================
# 4. Ceremony
# ==========================================================================
Write-Step 'Signing keys'

$OnlineKdbx      = $null
$OnlineKeyfile   = $null
$CeremonyRepoDir = $null

if ($SkipCeremony) {
    Write-Info 'Skipping the ceremony; point me at the existing material.'
    $OnlineKdbx = Read-Host '   Path to online.kdbx'
    if (-not (Test-Path $OnlineKdbx)) { Write-Fail "Not found: $OnlineKdbx"; exit 1 }
    $answer = Read-Host '   Path to the online keyfile (blank if the keystore has none)'
    if ($answer) {
        if (-not (Test-Path $answer)) { Write-Fail "Not found: $answer"; exit 1 }
        $OnlineKeyfile = $answer
    }
    $answer = Read-Host '   Path to the initialised repository directory (blank if the volumes are already seeded)'
    if ($answer) {
        if (-not (Test-Path $answer)) { Write-Fail "Not found: $answer"; exit 1 }
        $CeremonyRepoDir = $answer
    }
}
else {
    Write-Host "   Mode: $Mode" -ForegroundColor Gray
    if ($Mode -eq 'Production') {
        Write-Host '   Production requires a composite master key -- a password AND a key file,' -ForegroundColor Gray
        Write-Host '   in a different directory from the database, so that disclosure of one' -ForegroundColor Gray
        Write-Host '   location is not sufficient. Ideally a different device entirely.' -ForegroundColor Gray
    }
    else {
        Write-Warn 'Dev keyset: one operator, a known password, all five root keys together. Do not ship it.'
    }

    $CeremonyRepoDir = Read-Host '   Output directory for the initialised repository (e.g. C:\dist\repo)'
    if ((Test-Path $CeremonyRepoDir) -and (Get-ChildItem $CeremonyRepoDir -Force | Select-Object -First 1)) {
        Write-Fail "$CeremonyRepoDir exists and is not empty; the ceremony refuses to overwrite a keyset."
        exit 1
    }

    $offlineDb  = Read-Host '   Where to write offline.kdbx (root + targets)'
    $OnlineKdbx = Read-Host '   Where to write online.kdbx (snapshot, timestamp, apps)'

    $offlineKeyfile = $null
    if ($Mode -eq 'Production') {
        $offlineKeyfile = Read-Host '   Key file for offline.kdbx (must be in a different directory)'
        $OnlineKeyfile  = Read-Host '   Key file for online.kdbx (must be in a different directory)'

        # Mirror KeePassConfig.validate() before generating anything. Finding
        # this out after writing five root keys is a ceremony you redo.
        foreach ($p in @(@($offlineDb, $offlineKeyfile), @($OnlineKdbx, $OnlineKeyfile))) {
            $dbDir  = Split-Path -Parent ([IO.Path]::GetFullPath($p[0]))
            $kfDir  = Split-Path -Parent ([IO.Path]::GetFullPath($p[1]))
            if ($dbDir -eq $kfDir) {
                Write-Fail "Key file must not sit beside its database: $dbDir"
                exit 1
            }
            if ((Split-Path -Qualifier $dbDir) -eq (Split-Path -Qualifier $kfDir)) {
                Write-Warn "$([IO.Path]::GetFileName($p[0])) and its key file are on the same drive. The check passes; the intent (separate media) is not met."
            }
        }
    }

    $offlinePw = Read-Secret 'Password for offline.kdbx' -Confirm
    $onlinePw  = Read-Secret 'Password for online.kdbx'  -Confirm

    $ceremonyArgs = @('run', 'python', 'scripts/ceremony.py', '--out', $CeremonyRepoDir,
                      '--offline-db', $offlineDb, '--online-db', $OnlineKdbx,
                      '--passwords-from-stdin')
    if ($Mode -eq 'Dev') { $ceremonyArgs += '--dev' }
    else {
        $ceremonyArgs += @('--offline-keyfile', $offlineKeyfile, '--online-keyfile', $OnlineKeyfile)
        $env:ENV = 'production'
    }

    Write-Info 'Running the ceremony (passwords over stdin, never argv)...'
    Push-Location $RepoRoot
    try {
        # Two lines, offline first: the order _password() pops them in.
        "$offlinePw`n$onlinePw" | & uv @ceremonyArgs
        if ($LASTEXITCODE -ne 0) { throw "ceremony failed ($LASTEXITCODE)" }
    }
    finally {
        Pop-Location
        Remove-Item Env:\ENV -ErrorAction SilentlyContinue
        $offlinePw = $null; $onlinePw = $null
        [GC]::Collect()
    }
    Write-Ok 'Ceremony complete'

    if ($Mode -eq 'Production' -and -not (Test-Path $OnlineKeyfile)) {
        Write-Fail "The ceremony did not leave a key file at $OnlineKeyfile. Create one and re-run with -SkipCeremony."
        exit 1
    }

    # --- Get offline.kdbx off this machine ---------------------------------
    if (-not $AllowOfflineKeyOnHost) {
        Write-Host ''
        Write-Host '   offline.kdbx holds root (3-of-5) and targets (2-of-3). PLAN.md 3.3 is' -ForegroundColor Yellow
        Write-Host '   explicit that it must never sit on a machine with network access: it is' -ForegroundColor Yellow
        Write-Host '   the only thing between a host compromise and an attacker signing' -ForegroundColor Yellow
        Write-Host '   anything they like, indefinitely.' -ForegroundColor Yellow
        Write-Host ''
        $media = Read-Host '   Path on removable media to move it to (e.g. E:\tuf)'
        if ($media) {
            New-Item -ItemType Directory -Path $media -Force | Out-Null
            $target = Join-Path $media ([IO.Path]::GetFileName($offlineDb))
            Move-Item -Path $offlineDb -Destination $target
            if (Test-Path $offlineDb) { Write-Fail 'Move failed; offline.kdbx is still on this host.'; exit 1 }
            Write-Ok "Moved to $target"
            Write-Warn 'Back it up now. One copy is not a backup -- a single disk failure and you can never publish a new root.'
        }
        else {
            Write-Warn "offline.kdbx is still at $offlineDb, on a networked machine. Move it manually."
        }
    }
    elseif ($Mode -eq 'Production') {
        # Skipping silently would make the flag invisible in the run it
        # applied to, which is the one place it matters.
        Write-Warn "-AllowOfflineKeyOnHost: a PRODUCTION offline.kdbx was left at $offlineDb, on a networked machine. Move it to offline media and back it up."
    }
    else {
        Write-Info "-AllowOfflineKeyOnHost: offline.kdbx left at $offlineDb (Dev keyset, not for shipping)."
    }
}

# ==========================================================================
# 5. Secrets, and the mounts that make the *_FILE forms real
# ==========================================================================
Write-Step 'Secrets'

# The compose file reads FORGE_TOKEN_FILE and ONLINE_KDBX_PASSWORD_FILE but
# defines no `secrets:` section and mounts nothing at /run/secrets, so setting
# those paths alone would name a file that is not there. This generates the
# missing half as an override rather than editing the tracked compose file.

New-Item -ItemType Directory -Path $SecretsDir -Force | Out-Null
Protect-File $SecretsDir

$declared = [ordered]@{}

# --- online keystore password ----------------------------------------------
$pwFile = Join-Path $SecretsDir 'online_kdbx_password'
if (-not (Test-Path $pwFile)) {
    $pw = Read-Secret 'Password for online.kdbx (the signer needs it at runtime)'
    Set-Content -Path $pwFile -Value $pw -Encoding utf8NoBOM -NoNewline
    Protect-File $pwFile
    $pw = $null
    Write-Ok 'Wrote secrets\online_kdbx_password'
}
else { Write-Ok 'secrets\online_kdbx_password exists' }
$declared['online_kdbx_password'] = './secrets/online_kdbx_password'
$envMap['ONLINE_KDBX_PASSWORD_FILE'] = '/run/secrets/online_kdbx_password'

# --- online keystore key file ----------------------------------------------
if ($OnlineKeyfile) {
    $kfDest = Join-Path $SecretsDir 'online_kdbx_keyfile'
    if (-not (Test-Path $kfDest)) {
        Copy-Item -Path $OnlineKeyfile -Destination $kfDest
        Protect-File $kfDest
        Write-Ok 'Copied the online key file into secrets\'
        Write-Warn 'The key file now has a second copy beside the stack. That is what the signer needs to unseal on start; keep the authoritative copy elsewhere.'
    }
    $declared['online_kdbx_keyfile'] = './secrets/online_kdbx_keyfile'
    $envMap['ONLINE_KDBX_KEYFILE'] = '/run/secrets/online_kdbx_keyfile'
}

# --- forge token ------------------------------------------------------------
$tokenFile = Join-Path $SecretsDir 'forge_token'
if (-not (Test-Path $tokenFile)) {
    Write-Host '   A read-only forge token. Without one, public GitHub allows 60 requests an' -ForegroundColor Gray
    Write-Host '   hour per address and a single poll spends two, so a burst of releases' -ForegroundColor Gray
    Write-Host '   exhausts it and polls fail with 403. Nothing here writes to a forge.' -ForegroundColor Gray
    if (Confirm-Step 'Provide a forge token?' $true) {
        $tok = Read-Secret 'Forge token'
        Set-Content -Path $tokenFile -Value $tok -Encoding utf8NoBOM -NoNewline
        Protect-File $tokenFile
        $tok = $null
        Write-Ok 'Wrote secrets\forge_token'
    }
    else { Write-Warn 'No forge token. Expect 403 rate-limit failures on GitHub sources.' }
}
if (Test-Path $tokenFile) {
    $declared['forge_token'] = './secrets/forge_token'
    $envMap['FORGE_TOKEN_FILE'] = '/run/secrets/forge_token'
}

# --- generate the override --------------------------------------------------
$yaml = @(
    '# Generated by deploy\windows\Deploy-DistPlatform.ps1. Do not commit.',
    '#',
    '# docker-compose.yml reads *_FILE variables but declares no secrets and',
    '# mounts nothing at /run/secrets. This supplies that half. Compose bind-',
    '# mounts each file read-only at /run/secrets/<name>.',
    '',
    'secrets:'
)
foreach ($name in $declared.Keys) {
    $yaml += "  ${name}:"
    $yaml += "    file: $($declared[$name])"
}
$yaml += ''
$yaml += 'services:'
$yaml += '  signer:'
$yaml += '    secrets:'
foreach ($name in $declared.Keys | Where-Object { $_ -like 'online_kdbx_*' }) { $yaml += "      - $name" }
if ($declared.Contains('forge_token')) {
    $yaml += '  worker:'
    $yaml += '    secrets:'
    $yaml += '      - forge_token'
}
Set-Content -Path $SecretsFile -Value $yaml -Encoding utf8NoBOM
Write-Ok "Wrote $([IO.Path]::GetFileName($SecretsFile))"

Write-EnvFile $EnvFile $envMap
Write-Ok '.env updated with the in-container secret paths'

# ==========================================================================
# 6. Seed the volumes
# ==========================================================================
Write-Step 'Volumes'

# The signing-keys volume is the one nothing seeds on its own. A signer that
# exits immediately on start is almost always this.
$keysVolume = "${Project}_signing-keys"
if (-not (Test-DockerVolume $keysVolume)) { & docker volume create $keysVolume | Out-Null }

if ((Test-VolumeEmpty $keysVolume) -or $Force) {
    $staging = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        Copy-Item -Path $OnlineKdbx -Destination (Join-Path $staging 'online.kdbx')
        Copy-IntoVolume -Volume $keysVolume -Source $staging
        Write-Ok 'Seeded signing-keys with online.kdbx'
    }
    finally { Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue }
}
else { Write-Ok 'signing-keys already populated (-Force to re-seed)' }

# Repository metadata and targets from the ceremony.
if ($CeremonyRepoDir) {
    foreach ($pair in @(
        @{ Volume = "${Project}_tuf-metadata"; Source = (Join-Path $CeremonyRepoDir 'metadata') },
        @{ Volume = "${Project}_tuf-targets";  Source = (Join-Path $CeremonyRepoDir 'targets')  }
    )) {
        if (-not (Test-Path $pair.Source)) { Write-Warn "No $($pair.Source); skipping"; continue }
        if (-not (Test-DockerVolume $pair.Volume)) { & docker volume create $pair.Volume | Out-Null }
        if ((Test-VolumeEmpty $pair.Volume) -or $Force) {
            Copy-IntoVolume -Volume $pair.Volume -Source $pair.Source
            Write-Ok "Seeded $($pair.Volume)"
        }
        else { Write-Ok "$($pair.Volume) already populated" }
    }
}

# ==========================================================================
# 7. Build
# ==========================================================================
Write-Step 'Build'

Push-Location $RepoRoot
try { $env:DIST_BUILD_REF = (& git rev-parse --short HEAD).Trim() }
catch { $env:DIST_BUILD_REF = '' }
finally { Pop-Location }
$env:DIST_BUILD_TIME = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

Write-Info "Building all targets at $($env:DIST_BUILD_REF) (admin, worker and signer share one image)"
Invoke-Compose build
Write-Ok 'Images built'

# ==========================================================================
# 8. Up, and wait
# ==========================================================================
Write-Step 'Start'

Invoke-Compose up -d
Write-Ok 'Containers started'

$deadline = (Get-Date).AddMinutes(3)
$pending  = @('postgres', 'admin', 'edge')   # the three with healthchecks
while ((Get-Date) -lt $deadline -and $pending.Count -gt 0) {
    Start-Sleep -Seconds 3
    $still = @()
    foreach ($svc in $pending) {
        $cid = (& docker @((Get-ComposeArgs) + @('ps', '-q', $svc)) 2>$null | Select-Object -First 1)
        if (-not $cid) { $still += $svc; continue }
        $state = & docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $cid 2>$null
        if ($state -in @('healthy', 'running')) { Write-Ok "$svc is $state" } else { $still += $svc }
    }
    $pending = $still
}
if ($pending.Count -gt 0) {
    Write-Fail "Not healthy within 3 minutes: $($pending -join ', ')"
    Write-Host ''
    Write-Host '   Most likely causes, in order:' -ForegroundColor Yellow
    Write-Host '     signer exits at once  -> no keystore at /srv/keys/online.kdbx, or a bad password' -ForegroundColor Gray
    Write-Host '     admin will not settle -> POSTGRES_PASSWORD mismatch against an existing volume' -ForegroundColor Gray
    Write-Host ''
    Write-Host "   docker compose -p $Project logs --tail 50" -ForegroundColor Gray
    exit 1
}

# The signer has no healthcheck (no listener to probe). Check it stayed up.
$signerId = (& docker @((Get-ComposeArgs) + @('ps', '-q', 'signer')) 2>$null | Select-Object -First 1)
if ($signerId) {
    $signerState = & docker inspect -f '{{.State.Status}}' $signerId
    if ($signerState -ne 'running') {
        Write-Fail "The signer is '$signerState'. It has no healthcheck, so nothing else would have told you."
        & docker logs --tail 20 $signerId
        exit 1
    }
    Write-Ok 'signer is running'
}

# ==========================================================================
# 9. Which code is running
# ==========================================================================
Write-Step 'Verify'

if ($HasUv) {
    Push-Location $RepoRoot
    try { $tree = (& uv run python -m dist_core.buildinfo 2>$null) -join ' ' } catch { $tree = '' }
    finally { Pop-Location }
    if ($tree) { Write-Info "tree   : $tree" }
}
try {
    $health = Invoke-RestMethod -Uri "http://$($envMap['ADMIN_BIND']):$($envMap['ADMIN_PORT'])/healthz" -TimeoutSec 5
    Write-Info "admin  : $($health | ConvertTo-Json -Compress -Depth 3)"
}
catch { Write-Warn "Could not read the admin /healthz endpoint: $($_.Exception.Message)" }

$workerLine = (& docker @((Get-ComposeArgs) + @('logs', '--tail', '200', 'worker')) 2>$null |
               Where-Object { $_ -match 'starting; source' } | Select-Object -First 1)
if ($workerLine) { Write-Info "worker : $workerLine" }

Write-Host ''
Write-Host '   Three matching `source` digests mean the containers are running your tree.' -ForegroundColor Gray
Write-Host '   A worker that disagrees with the other two is the case that is otherwise' -ForegroundColor Gray
Write-Host '   invisible -- it reports failures describing code no longer on disk.' -ForegroundColor Gray

try {
    $null = Invoke-WebRequest -Uri "http://$($envMap['EDGE_BIND']):$($envMap['EDGE_PORT'])/healthz" -TimeoutSec 5
    Write-Ok 'edge /healthz responds'
}
catch { Write-Warn "edge /healthz did not respond: $($_.Exception.Message)" }

# ==========================================================================
# 10. What is left, which is not nothing
# ==========================================================================
Write-Step 'Deployed'

if ($script:Warnings.Count -gt 0) {
    Write-Host ''
    Write-Host "   $($script:Warnings.Count) warning(s):" -ForegroundColor Yellow
    $script:Warnings | ForEach-Object { Write-Host "     - $_" -ForegroundColor Yellow }
}

Write-Host ''
Write-Host '   Admin UI  ' -NoNewline; Write-Host "http://$($envMap['ADMIN_BIND']):$($envMap['ADMIN_PORT'])" -ForegroundColor Cyan
Write-Host '   Edge      ' -NoNewline; Write-Host "http://$($envMap['EDGE_BIND']):$($envMap['EDGE_PORT'])" -ForegroundColor Cyan
Write-Host ''
Write-Host '   Still to do, none of which this script can do for you:' -ForegroundColor White
Write-Host ''
Write-Host '   1. Put a TLS terminator in front of both ports. Neither is exposed and' -ForegroundColor Gray
Write-Host '      ADMIN_SECURE_COOKIE stays 0 until one is there.' -ForegroundColor Gray
Write-Host '   2. Register a source in the admin UI. It will stop at pending_delegation:' -ForegroundColor Gray
Write-Host '      serving an application needs an app-<id> delegation, targets signs' -ForegroundColor Gray
Write-Host '      2-of-3 offline, and a web form is forbidden from touching TUF metadata.' -ForegroundColor Gray
Write-Host '   3. Run the delegation ceremony on the offline machine, then activate:' -ForegroundColor Gray
Write-Host '        uv run python -m dist_registry.delegate <app-id> --repo <repo>' -ForegroundColor DarkGray
Write-Host '   4. Wire a malware scanner, or accept the recorded SKIP_GATES entry.' -ForegroundColor Gray
Write-Host ''
Write-Host '   Do not commit: deploy\compose\.env, deploy\compose\secrets\,' -ForegroundColor DarkGray
Write-Host '   deploy\compose\docker-compose.secrets.yml' -ForegroundColor DarkGray
Write-Host ''
