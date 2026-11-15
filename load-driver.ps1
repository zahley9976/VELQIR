# VELQIR driver loader - script mode.
# 1-driver.bat -> this file -> zxmapper.exe kernel-mode.sys
#
# zxmapper is the same mapper build the previous NightRun release shipped with.
# It fixes the target's GS cookie before calling entry (this driver's
# __security_init_cookie fastfails on zero/default cookie), so entry 0x8000
# runs normally. After mapping it cleans its own traces and unloads the
# vulnerable driver it borrowed.
#
# After the map this script: sweeps the mapper's registry/temp leftovers (EAC
# refuses to start the game while they exist), probes the device, widens its
# DACL so the overlay runs without UAC, writes the session file and starts the
# hidden watcher that pulls the remote payload once ROB RUN appears.
param(
    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'

# ---- self-elevate ----
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $extra = ''
    if ($NoPause) { $extra = ' -NoPause' }
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"' + $extra) -ErrorAction Stop
    } catch {
        # a declined UAC prompt throws; without this the window vanishes and the
        # user is left thinking the kit ran when nothing was loaded at all
        Write-Host ''
        Write-Host '[!] UAC was declined.' -ForegroundColor Red
        Write-Host '    The driver is not loaded, the watcher never started, nothing will be fetched.' -ForegroundColor Red
        Write-Host '    Run 1-driver.bat again and press Yes.' -ForegroundColor Red
        Write-Host ''
        Read-Host 'Press Enter to close'
        exit 1
    }
    exit
}

$dir = $PSScriptRoot

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class VqDev
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr templ);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint rev, out IntPtr sd, IntPtr sz);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetSecurityDescriptorDacl(IntPtr sd, out bool present, out IntPtr dacl, out bool deflt);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint SetSecurityInfo(IntPtr h, int objType, uint secInfo, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr p);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool LookupPrivilegeValueW(string sys, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool all, ref TokPriv state, int len, IntPtr prev, IntPtr ret);
    [DllImport("ntdll.dll")]
    static extern int NtUnloadDriver(ref Ustr name);

    [StructLayout(LayoutKind.Sequential)]
    struct TokPriv { public int Count; public int LuidLow; public int LuidHigh; public int Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct Ustr { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    const string DEV = "\\\\?\\GLOBALROOT\\Device\\WhReader4";
    const string NAL = "\\\\?\\GLOBALROOT\\Device\\Nal";

    static bool EnableLoadDriver()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020u | 0x0008u, out token)) return false;
        long luid;
        if (!LookupPrivilegeValueW(null, "SeLoadDriverPrivilege", out luid)) return false;
        TokPriv tp = new TokPriv();
        tp.Count = 1;
        tp.LuidLow = (int)(luid & 0xFFFFFFFFL);
        tp.LuidHigh = (int)(luid >> 32);
        tp.Attributes = 0x2;
        return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }

    // unloads a driver loaded via NtLoadDriver; returns 0, 0xC0000034 when not
    // loaded, or another NTSTATUS. iqvw64e outlives a killed mapper, and while
    // it is resident EAC refuses to start the game.
    public static int UnloadDriver(string servicePath)
    {
        if (!EnableLoadDriver()) return -1;
        IntPtr buf = Marshal.StringToHGlobalUni(servicePath);
        try {
            Ustr u = new Ustr();
            u.Length = (ushort)(servicePath.Length * 2);
            u.MaximumLength = (ushort)(servicePath.Length * 2 + 2);
            u.Buffer = buf;
            return NtUnloadDriver(ref u);
        } finally { Marshal.FreeHGlobal(buf); }
    }

    public static bool NalUp()
    {
        IntPtr h = CreateFileW(NAL, 0, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        if (h == new IntPtr(-1)) return false;
        CloseHandle(h);
        return true;
    }

    // 0 = absent, 1 = open with full access, 2 = object exists but access denied
    public static int Probe()
    {
        IntPtr h = CreateFileW(DEV, 0xC0000000, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        if (h != new IntPtr(-1)) { CloseHandle(h); return 1; }
        int e1 = Marshal.GetLastWin32Error();
        IntPtr h2 = CreateFileW(DEV, 0x80 /*FILE_READ_ATTRIBUTES*/, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        if (h2 != new IntPtr(-1)) { CloseHandle(h2); return 2; }
        int e2 = Marshal.GetLastWin32Error();
        if (e1 == 5 || e2 == 5) return 2;
        return 0;
    }

    public static bool IsUp() { return Probe() != 0; }

    public static bool Grant()
    {
        IntPtr sd;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:(A;;GA;;;WD)", 1, out sd, IntPtr.Zero)) return false;
        try {
            IntPtr h = CreateFileW(DEV, 0x00040000u | 0x00020000u, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
            if (h == new IntPtr(-1)) return false;
            try {
                bool present, deflt;
                IntPtr dacl;
                if (!GetSecurityDescriptorDacl(sd, out present, out dacl, out deflt)) return false;
                return SetSecurityInfo(h, 6, 4, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero) == 0;
            } finally { CloseHandle(h); }
        } finally { LocalFree(sd); }
    }
}
'@

function Write-Session {
    $session = [ordered]@{
        device = '\\?\GLOBALROOT\Device\WhReader4'
        read   = 2254852
        base   = 2254860
        attach = 2271232
        detach = 2271240
    }
    $json = $session | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $dir 'velqir.session.json'), $json)
}

function Close-Or-Pause {
    if (-not $NoPause) { Read-Host 'Press Enter to close' }
}

$log = Join-Path $dir 'loader.log'
try { [IO.File]::WriteAllText($log, '') } catch { }
function Log([string]$s) {
    Write-Host $s
    try { [IO.File]::AppendAllText($log, ((Get-Date).ToString('HH:mm:ss.fff') + '  ' + $s + "`r`n")) } catch { }
}

function Start-GameWatcher {
    $script = Join-Path $dir 'game-watcher.ps1'
    if (!(Test-Path -LiteralPath $script)) { Log '[!] game-watcher.ps1 missing - watcher not started'; return }
    $running = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like '*game-watcher.ps1*' })
    if ($running.Count -gt 0) {
        Log ('[*] watcher already running (pid ' + $running[0].ProcessId + ')')
        return
    }
    $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $script + '"'
    try {
        # inherits this elevated token: the payload it launches never sees UAC
        $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -WindowStyle Hidden -PassThru
        Log ('[+] watcher started (pid ' + $p.Id + ') - waits for ROB RUN')
    } catch {
        Log ('[!] watcher start failed: ' + $_.Exception.Message)
    }
}

# zxmapper drops the vulnerable driver as a service with a random name:
#   HKLM\SYSTEM\CurrentControlSet\Services\<random>  Type=1  ImagePath=\??\%TEMP%\<random>
# and never deletes either the key or the file (the build has RegCreateKeyW
# but no RegDeleteKey). EAC refuses to start the game while that key exists,
# so every run sweeps the leftovers - before the map (old ones) and after it
# (the fresh one this run created).
function Remove-ResidueFile([string]$path) {
    if (!(Test-Path -LiteralPath $path)) { return $false }
    try {
        Set-ItemProperty -LiteralPath $path -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        Log ('[+] removed leftover image: ' + $path)
        return $true
    } catch { }
    & takeown.exe /f $path | Out-Null
    & icacls.exe $path /grant '*S-1-5-32-544:F' | Out-Null
    try {
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        Log ('[+] removed leftover image (takeown): ' + $path)
        return $true
    } catch {
        Log ('[!] could not remove ' + $path + ': ' + $_.Exception.Message)
        return $false
    }
}

function Clear-MapperResidue {
    foreach ($stale in (Get-Process -Name 'zxmapper' -ErrorAction SilentlyContinue)) {
        try { Stop-Process -Id $stale.Id -Force; Log ('[!] killed stale mapper pid ' + $stale.Id) } catch { }
    }
    $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $keys = 0
    $files = 0
    Get-ChildItem $svcRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if (!$props.ImagePath) { return }
        if ($props.Type -ne 1 -and $props.Type) { return }
        $img = [string]$props.ImagePath
        if ($img -notmatch '(?i)\\AppData\\Local\\Temp\\') { return }
        $name = $_.PSChildName
        # a killed mapper leaves iqvw64e resident; unload it first, otherwise
        # EAC keeps seeing it in the loaded-module list
        $rc = [VqDev]::UnloadDriver('\Registry\Machine\System\CurrentControlSet\Services\' + $name)
        if ($rc -eq 0) {
            Log ('[+] unloaded leftover driver: ' + $name)
        } elseif ($rc -eq -1073741772) {
            # 0xC0000034 - not loaded, nothing to unload
        } else {
            # keep the key: without it the driver could never be unloaded again
            Log ('[!] unload ' + $name + ' failed, status=' + $rc + ' - key kept for the next run')
            return
        }
        try {
            Remove-Item -LiteralPath (Join-Path $svcRoot $name) -Recurse -Force -ErrorAction Stop
            $keys++
            Log ('[+] removed leftover service key: ' + $name)
        } catch {
            Log ('[!] could not remove service key ' + $name + ': ' + $_.Exception.Message)
        }
        $file = $img -replace '^\\\?\?\\', ''
        $file = $file.Trim('"')
        if (Remove-ResidueFile $file) { $files++ }
    }
    # orphan images: same random name, same size, PE header or zeroed remnant
    Get-ChildItem $env:TEMP -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '^[A-Za-z]{12,24}$' -and $_.Length -eq 34568
    } | ForEach-Object {
        try {
            $fs = [IO.File]::OpenRead($_.FullName)
            $hdr = New-Object byte[] 16
            $null = $fs.Read($hdr, 0, 16)
            $fs.Close()
        } catch { return }
        $isMz = ($hdr[0] -eq 0x4D -and $hdr[1] -eq 0x5A)
        $isZero = $true
        foreach ($b in $hdr) { if ($b -ne 0) { $isZero = $false; break } }
        if (!$isMz -and !$isZero) { return }
        if (Remove-ResidueFile $_.FullName) { $files++ }
    }
    if ($keys -gt 0 -or $files -gt 0) {
        Log ('[*] residue sweep: keys=' + $keys + ' files=' + $files)
    } else {
        Log '[*] residue sweep: clean'
    }
    $left = @(Get-ChildItem $svcRoot -ErrorAction SilentlyContinue | Where-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $p.Type -eq 1 -and $p.ImagePath -and ([string]$p.ImagePath -match '(?i)\\AppData\\Local\\Temp\\')
    })
    if ($left.Count -gt 0) {
        Log ('[!] mapper service keys still present: ' + (($left | ForEach-Object { $_.PSChildName }) -join ', '))
    }
    if ([VqDev]::NalUp()) {
        Log '[!] iqvw64e is still resident - EAC will block the game until reboot'
    }
}

Log ('velqir loader start, elevated=' + $true)

if (Get-Process -Name 'ROB RUN' -ErrorAction SilentlyContinue) {
    Log '[-] ROB RUN is running. Close the game first - the driver loads only with the game closed.'
    Close-Or-Pause
    exit 1
}

Clear-MapperResidue

$probe = [VqDev]::Probe()
if ($probe -ne 0) {
    Log ('[+] VELQIR driver already loaded (probe=' + $probe + ')')
    foreach ($stale in (Get-Process -Name 'zxmapper' -ErrorAction SilentlyContinue)) {
        try { Stop-Process -Id $stale.Id -Force; Log ('[!] killed stale mapper pid ' + $stale.Id) } catch { }
    }
} else {
    $mapper = Join-Path $dir 'zxmapper.exe'
    $sys = Join-Path $dir 'kernel-mode.sys'
    if (!(Test-Path -LiteralPath $mapper)) { Log ('[-] mapper not found: ' + $mapper); Close-Or-Pause; exit 2 }
    if (!(Test-Path -LiteralPath $sys)) { Log '[-] kernel-mode.sys not found next to the script'; Close-Or-Pause; exit 2 }

    Log '[*] mapping driver...'
    # the mapper can hang after its last line - watch the kernel instead of
    # waiting on the process forever, but never kill it before it has finished
    # its own cleanup (trace strip + iqvw64e unload)
    $empty = Join-Path $env:TEMP 'velqir_empty_stdin.txt'
    try { [IO.File]::WriteAllText($empty, '') } catch { }
    $mp = Start-Process -FilePath $mapper -ArgumentList ('"' + $sys + '"') -NoNewWindow -PassThru -RedirectStandardInput $empty
    $probe = 0
    for ($i = 0; $i -lt 240; $i++) {
        $probe = [VqDev]::Probe()
        if ($probe -ne 0) { break }
        if ($mp.HasExited) { break }
        Start-Sleep -Milliseconds 250
    }
    if ($probe -ne 0) {
        Log ('[+] device present (probe=' + $probe + '), waiting for mapper cleanup...')
        # iqvw64e exposed as \Device\Nal; when it disappears the mapper has
        # unloaded the borrowed driver and only its exit is left
        for ($i = 0; $i -lt 120; $i++) {
            if ($mp.HasExited) { break }
            if (-not [VqDev]::NalUp()) { break }
            Start-Sleep -Milliseconds 250
        }
        $mp.WaitForExit(5000) | Out-Null
        if ($mp.HasExited) {
            $code = 'n/a'
            try { $code = $mp.ExitCode } catch { }
            Log ('[*] mapper exit code: ' + $code)
        } else {
            Log '[!] mapper did not exit after unloading - terminating it'
            try { Stop-Process -Id $mp.Id -Force } catch { }
        }
    } elseif ($mp.HasExited) {
        Log ('[-] mapper exited before the device appeared, code ' + $mp.ExitCode)
    }
    if ($probe -eq 0) {
        Log '[-] device did not appear after mapping'
        Log '    send dist\loader.log'
        Close-Or-Pause
        exit 3
    }
    Log ('[+] device present after mapping (probe=' + $probe + ')')
    # the mapper created a fresh service key + temp image for the driver it
    # borrowed; this run is done with it, so clean it before EAC ever sees it
    Clear-MapperResidue
}

if ([VqDev]::Grant()) { Log '[+] device DACL widened (overlay can run without UAC)' }
else { Log '[!] DACL widen failed - overlay will ask for UAC (fine)' }

Write-Session
Start-GameWatcher
Log '[+] VELQIR driver loaded'
Close-Or-Pause
exit 0
