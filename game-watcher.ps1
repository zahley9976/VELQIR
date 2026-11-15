# game-watcher.ps1 - background half of the VELQIR kit.
#
# Started by load-driver.ps1 inside the elevated window, so whatever it spawns
# later inherits admin and never asks for UAC again.
#
# It waits for ROB RUN, then pulls the remote payload into the game folder and
# launches it from there. Nothing is downloaded before the game shows up.
# Every game session checks all configured files: the ones that changed on the
# host are replaced, the untouched ones are left alone; the launchable exe is
# restarted so a stale copy is never what stays on screen.
# Create watcher.stop next to this file to end it.

param(
    [string]$ConfigPath = '',
    [int]$PollMs = 1500
)

$dir = $PSScriptRoot
if ($ConfigPath -eq '') { $ConfigPath = Join-Path $dir 'velqir.remote.json' }
$fetch = Join-Path $dir 'remote-fetch.ps1'
if (Test-Path -LiteralPath $fetch) { . $fetch }

$logPath = Join-Path $dir 'watcher.log'
$stopFile = Join-Path $dir 'watcher.stop'

$gameExe = 'ROB RUN.exe'
$steamApp = 'Rob Run'

function WLog([string]$s) {
    $line = (Get-Date).ToString('HH:mm:ss.fff') + '  ' + $s
    try { [IO.File]::AppendAllText($logPath, $line + "`r`n") } catch { }
}

# ---------------------------------------------------------------- path helpers

function Normalize-Dir([string]$p) {
    if (!$p) { return '' }
    $p = $p.Trim().Trim('"').Replace('/', '\')
    if (!$p) { return '' }
    try { $p = [IO.Path]::GetFullPath($p) } catch { return '' }
    if (![IO.Directory]::Exists($p)) { return '' }
    return $p.TrimEnd('\')
}

# folder of an exe path, only when that exe really exists on disk
function Get-FolderOfExe([string]$path) {
    if (!$path) { return '' }
    $p = $path.Trim().Trim('"').Replace('/', '\')
    if (!$p) { return '' }
    try { $p = [IO.Path]::GetFullPath($p) } catch { return '' }
    if (![IO.File]::Exists($p)) { return '' }
    $d = [IO.Path]::GetDirectoryName($p)
    if ($d -and [IO.Directory]::Exists($d)) { return $d.TrimEnd('\') }
    return ''
}

# --------------------------------------------------------------- resolvers
# EAC shields the game: Process.Path and MainModule.FileName come back empty
# even with admin rights, and WMI usually blanks ExecutablePath too. So the
# folder is recovered from what the shell itself left behind.

function Resolve-FromLauncher {
    # start_protected_game.exe is EAC's own launcher, unprotected, same folder
    $p = Get-Process -Name 'start_protected_game' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (!$p) { return '' }
    try { if ($p.Path) { $d = Get-FolderOfExe $p.Path; if ($d) { return $d } } } catch { }
    try {
        $ci = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $p.Id) -ErrorAction SilentlyContinue
        if ($ci -and $ci.ExecutablePath) { $d = Get-FolderOfExe $ci.ExecutablePath; if ($d) { return $d } }
    } catch { }
    return ''
}

function Resolve-FromProcess($proc) {
    try { if ($proc.Path) { $d = Get-FolderOfExe $proc.Path; if ($d) { return $d } } } catch { }
    try {
        $p = Get-Process -Id $proc.Id -ErrorAction Stop
        if ($p.MainModule -and $p.MainModule.FileName) {
            $d = Get-FolderOfExe $p.MainModule.FileName
            if ($d) { return $d }
        }
    } catch { }
    try {
        $ci = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $proc.Id) -ErrorAction SilentlyContinue
        if ($ci -and $ci.ExecutablePath) { $d = Get-FolderOfExe $ci.ExecutablePath; if ($d) { return $d } }
    } catch { }
    return ''
}

function Resolve-FromMuiCache {
    # Explorer writes "<full path>.exe.FriendlyAppName" on first launch
    $key = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
    if (!(Test-Path -LiteralPath $key)) { return '' }
    $names = @()
    try { $names = (Get-Item -LiteralPath $key).GetValueNames() } catch { return '' }
    $fallback = ''
    foreach ($n in $names) {
        if ($n -notmatch '(?i)^([A-Z]:[\\/].+?\.exe)\.(?:FriendlyAppName|ApplicationCompany)$') { continue }
        $exe = $Matches[1]
        $leaf = ''
        try { $leaf = [IO.Path]::GetFileName($exe) } catch { continue }
        if ($leaf -notmatch '(?i)^ROB RUN\.exe$') { continue }
        $d = Get-FolderOfExe $exe
        if (!$d) { continue }
        if ([IO.File]::Exists((Join-Path $d $gameExe))) { return $d }
        if (!$fallback) { $fallback = $d }
    }
    return $fallback
}

function Get-SteamLibraryRoots {
    $roots = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $keys = @('HKCU:\Software\Valve\Steam', 'HKLM:\SOFTWARE\Valve\Steam', 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam')
    foreach ($k in $keys) {
        $v = $null
        try { $v = Get-ItemProperty -LiteralPath $k -ErrorAction Stop } catch { continue }
        foreach ($prop in @('SteamPath', 'InstallPath')) {
            $val = $null
            try { $val = $v.$prop } catch { }
            if (!$val) { continue }
            $d = Normalize-Dir ([string]$val)
            if ($d -and $seen.Add($d)) { $roots.Add($d) }
        }
    }
    foreach ($r in @($roots)) {
        $vdf = Join-Path $r 'steamapps\libraryfolders.vdf'
        if (!(Test-Path -LiteralPath $vdf)) { continue }
        $text = ''
        try { $text = [IO.File]::ReadAllText($vdf) } catch { continue }
        foreach ($m in [regex]::Matches($text, '"path"\s*"([^"]+)"')) {
            $raw = $m.Groups[1].Value.Replace('\\', '\')
            $d = Normalize-Dir $raw
            if ($d -and $seen.Add($d)) { $roots.Add($d) }
        }
    }
    return $roots
}

function Resolve-FromSteam {
    foreach ($lib in (Get-SteamLibraryRoots)) {
        $common = Join-Path $lib 'steamapps\common'
        if (!(Test-Path -LiteralPath $common)) { continue }
        $direct = Join-Path $common ($steamApp + '\' + $gameExe)
        if ([IO.File]::Exists($direct)) { return [IO.Path]::GetDirectoryName($direct) }
        $hit = Get-ChildItem -LiteralPath $common -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName $gameExe } |
            Where-Object { [IO.File]::Exists($_) } |
            Select-Object -First 1
        if ($hit) { return [IO.Path]::GetDirectoryName($hit) }
    }
    return ''
}

function Resolve-FromDrives {
    # last resort: shallow globs, fixed drives only
    $drives = @()
    try {
        $drives = [IO.DriveInfo]::GetDrives() |
            Where-Object { $_.IsReady -and $_.DriveType -eq 'Fixed' } |
            ForEach-Object { $_.RootDirectory.FullName }
    } catch { return '' }
    $patterns = @(
        'steamapps\common\*\',
        'Steam\steamapps\common\*\',
        'SteamLibrary\steamapps\common\*\',
        'Games\*\',
        'Games\*\*\',
        '*\'
    )
    foreach ($d in $drives) {
        foreach ($pat in $patterns) {
            $hit = $null
            try {
                $hit = Get-ChildItem -Path ($d + $pat + $gameExe) -File -ErrorAction SilentlyContinue | Select-Object -First 1
            } catch { continue }
            if ($hit) { return $hit.DirectoryName }
        }
    }
    return ''
}

function Get-GameFolder($proc, [string]$hint) {
    if ($hint) {
        $d = Normalize-Dir $hint
        if ($d) { return [pscustomobject]@{ Dir = $d; Source = 'config game_dir' } }
    }
    $d = Resolve-FromLauncher
    if ($d) { return [pscustomobject]@{ Dir = $d; Source = 'start_protected_game.exe' } }
    $d = Resolve-FromProcess $proc
    if ($d) { return [pscustomobject]@{ Dir = $d; Source = 'process path' } }
    $d = Resolve-FromMuiCache
    if ($d) { return [pscustomobject]@{ Dir = $d; Source = 'MuiCache' } }
    $d = Resolve-FromSteam
    if ($d) { return [pscustomobject]@{ Dir = $d; Source = 'steam library' } }
    $d = Resolve-FromDrives
    if ($d) { return [pscustomobject]@{ Dir = $d; Source = 'drive scan' } }
    return $null
}

# ---------------------------------------------------------------- main loop

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    WLog ('watcher start, pid=' + $PID + ' elevated=True - launched files inherit admin, no UAC')
} else {
    # started outside the elevated window: every launch below lands in a Medium
    # token, which is exactly the case the kit is not built for
    WLog ('watcher start, pid=' + $PID + ' elevated=False')
    WLog '[!] NOT ELEVATED - the payload will run without admin. Close this and run 1-driver.bat, then accept UAC.'
}
WLog ('config: ' + $ConfigPath + ' exists=' + (Test-Path -LiteralPath $ConfigPath))

$handledId = 0
$seenId = 0
$configWarned = $false
$failLoggedFor = 0
$fetchFails = 0

while ($true) {
    if (Test-Path -LiteralPath $stopFile) {
        WLog 'stop file found - exit'
        Remove-Item -LiteralPath $stopFile -Force -ErrorAction SilentlyContinue
        break
    }

    $game = Get-Process -Name 'ROB RUN' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (!$game) {
        $handledId = 0
        $seenId = 0
        $failLoggedFor = 0
        $fetchFails = 0
        Start-Sleep -Milliseconds $PollMs
        continue
    }
    if ($game.Id -eq $handledId) {
        Start-Sleep -Milliseconds $PollMs
        continue
    }
    if ($game.Id -ne $seenId) {
        $seenId = $game.Id
        WLog ('[+] ROB RUN started: pid ' + $game.Id)
    }

    $cfg = $null
    if (Test-Path -LiteralPath $ConfigPath) { $cfg = Read-RemoteConfig $ConfigPath }
    if (!$cfg) {
        if (!$configWarned) { WLog '[-] no valid velqir.remote.json - nothing to fetch'; $configWarned = $true }
        Start-Sleep -Milliseconds $PollMs
        continue
    }
    $configWarned = $false

    $hint = [string](Get-ConfigValue $cfg 'game_dir' '')
    $found = Get-GameFolder $game $hint
    if (!$found) {
        if ($failLoggedFor -ne $game.Id) {
            WLog ('[-] game folder not resolved yet (pid ' + $game.Id + ') - still trying')
            $failLoggedFor = $game.Id
        }
        Start-Sleep -Milliseconds 1000
        continue
    }

    $gameDir = $found.Dir
    $handledId = $game.Id
    WLog ('[+] game folder: ' + $gameDir + '  (' + $found.Source + ')')

    $plan = @(Get-RemotePlan $gameDir $cfg)
    if ($plan.Count -eq 0) {
        WLog '[-] config lists no files to fetch'
        Start-Sleep -Milliseconds $PollMs
        continue
    }

    # every game session gets a fresh build: old instances are stopped first so
    # the image locks are gone and no stale binary stays on screen
    $killOld = [bool](Get-ConfigValue $cfg 'kill_old' $true)
    $stoppedAny = $false
    if ($killOld) {
        foreach ($f in $plan) {
            if (!$f.Launch) { continue }
            $procName = [IO.Path]::GetFileNameWithoutExtension($f.Name)
            foreach ($o in @(Get-Process -Name $procName -ErrorAction SilentlyContinue)) {
                try {
                    Stop-Process -Id $o.Id -Force -ErrorAction Stop
                    WLog ('[*] stopped old ' + $procName + ' (pid ' + $o.Id + ') - replacing it')
                    $stoppedAny = $true
                } catch {
                    WLog ('[!] cannot stop old ' + $procName + ' (pid ' + $o.Id + '): ' + $_.Exception.Message)
                }
            }
        }
        if ($stoppedAny) { Start-Sleep -Milliseconds 800 }
    }

    $failed = $false
    foreach ($f in $plan) {
        # half-written leftovers from an interrupted run would only trip the retries
        Remove-Item -LiteralPath ($f.Path + '.part') -Force -ErrorAction SilentlyContinue
        WLog ('[*] fetching ' + $f.Name + ' -> ' + $f.Path)
        $r = Get-RemoteFile -dest $f.Path -cfg $f.Config
        if ($r.Ok) {
            if ($r.Changed) {
                WLog ('[+] updated: ' + $f.Path + ' (' + $r.Message + ')')
            } else {
                WLog ('[=] ' + $f.Name + ' already current on disk (' + $r.Message + ')')
            }
            continue
        }
        if (!$f.Launch) {
            # the game itself may hold a dll open - that must not block the exe
            WLog ('[!] ' + $f.Name + ' not updated: ' + $r.Message + ' - old copy stays')
            continue
        }
        $fetchFails++
        WLog ('[!] fetch failed: ' + $f.Name + ': ' + $r.Message + ' (attempt ' + $fetchFails + '/5)')
        $failed = $true
        break
    }

    if ($failed) {
        if ($fetchFails -lt 5) {
            $handledId = 0
            $failLoggedFor = 0
            Start-Sleep -Milliseconds 3000
            continue
        }
        WLog '[-] giving up on updating this session'
        $fetchFails = 0
        if (![bool](Get-ConfigValue $cfg 'launch_stale' $true)) {
            WLog '[*] launch_stale=false - nothing is launched'
            Start-Sleep -Milliseconds $PollMs
            continue
        }
    } else {
        $fetchFails = 0
    }

    $toLaunch = @($plan | Where-Object { $_.Launch })
    if ($toLaunch.Count -eq 0) {
        WLog '[*] nothing marked for launch - files left in place'
        Start-Sleep -Milliseconds $PollMs
        continue
    }

    # the launchable file always runs: freshly written when the host had an
    # update, the copy already on disk when the host is unreachable
    foreach ($f in $toLaunch) {
        if (!(Test-Path -LiteralPath $f.Path)) {
            WLog ('[!] ' + $f.Name + ' is missing and cannot be fetched - nothing to launch')
            continue
        }
        if ($failed) {
            WLog ('[!] launching the copy already on disk: ' + $f.Name)
        }
        try {
            $p = Start-Process -FilePath $f.Path -WorkingDirectory $gameDir -PassThru
            WLog ('[+] started ' + $f.Name + ' (pid ' + $p.Id + ')')
            # a pid alone proves nothing: a payload that dies on startup still
            # gets one, and the log would read as a clean launch forever
            Start-Sleep -Milliseconds 1500
            if ($p.HasExited) {
                WLog ('[!] ' + $f.Name + ' exited right away, code ' + $p.ExitCode + ' - the binary is broken, not the launcher')
            } else {
                WLog ('[+] ' + $f.Name + ' is running (pid ' + $p.Id + ', elevated=' + $isAdmin + ')')
            }
        } catch {
            WLog ('[!] launch failed: ' + $f.Name + ': ' + $_.Exception.Message)
        }
    }
    Start-Sleep -Milliseconds $PollMs
}

WLog 'watcher exit'
exit 0
