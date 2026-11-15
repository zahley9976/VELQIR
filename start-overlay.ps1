$dir = $PSScriptRoot
$exe = Join-Path $dir 'VELQIR.exe'
$session = Join-Path $dir 'velqir.session.json'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class DevOpen{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern IntPtr CreateFileW(string n,int a,int s,IntPtr se,int c,int f,IntPtr t);[DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr h);}'

function Resolve-Device([string]$path) {
    if ([string]::IsNullOrEmpty($path)) { return '\\?\GLOBALROOT\Device\WhReader4' }
    if ($path.StartsWith('\\.\')) { return '\\?\GLOBALROOT\Device\' + $path.Substring(4) }
    return $path
}

function Test-Device([string]$path) {
    $h = [DevOpen]::CreateFileW($path, -1073741824, 3, [IntPtr]::Zero, 3, 128, [IntPtr]::Zero)
    if ($h -eq [IntPtr](-1)) { return $false }
    [DevOpen]::CloseHandle($h) | Out-Null
    return $true
}

try {
    if (!(Test-Path $exe)) { throw ('VELQIR.exe not found: ' + $exe) }

    $device = '\\?\GLOBALROOT\Device\WhReader4'
    if (Test-Path $session) {
        try { $device = Resolve-Device (Get-Content $session -Raw | ConvertFrom-Json).device } catch { }
    }

    if (!(Test-Device $device)) {
        if (-not $isAdmin) {
            # device DACL is SY/BA only unless the loader widened it - same UAC flow as NightRun
            Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"')
            exit
        }
        throw 'VELQIR driver is not loaded. Run 1-driver.bat first (game must be closed).'
    }

    $game = Get-Process -Name 'ROB RUN' -ErrorAction SilentlyContinue
    if (!$game) { Write-Host 'Warning: ROB RUN is not running. Start the game, the overlay will show OFFLINE until then.' -ForegroundColor Yellow }

    foreach ($instance in (Get-Process -Name VELQIR -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $instance.Id -ErrorAction Stop
        $instance.WaitForExit(10000) | Out-Null
    }
    if (Get-Process -Name VELQIR -ErrorAction SilentlyContinue) { throw 'Old VELQIR did not exit.' }

    $new = Start-Process -FilePath $exe -WorkingDirectory $dir -PassThru
    Write-Host ('VELQIR started, PID ' + $new.Id)
    Start-Sleep -Seconds 3
    if ($new.HasExited) { throw ('VELQIR exited immediately, code ' + $new.ExitCode) }
    Write-Host 'Overlay is running. Keep the game window focused to see ESP.'
    Read-Host 'Press Enter to close'
} catch {
    Write-Host ('FAILED: ' + $_.Exception.Message) -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}
