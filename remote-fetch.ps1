# remote-fetch.ps1 - shared downloader for the VELQIR kit.
#
# Config lives next to the caller (velqir.remote.json):
#   url            direct link; when set it wins over the GitHub block.
#                  a "{file}" inside it is replaced by each file name
#   owner/repo     GitHub repository
#   tag            "latest" or a release tag
#   asset          asset file name inside the release (first asset when empty)
#   token          API key / PAT; empty for public repos
#   sha256         optional integrity check of the downloaded file
#   files          list of names or objects: { "name": ..., "url": ..., "launch": ... }
#   game_file      legacy single-file name when "files" is absent
#   launch         true = run it after the download
#
# Every download is streamed to a .part file and compared with the copy already
# on disk: identical bytes mean nothing is replaced, so a dll the game keeps
# open is not touched for nothing.
#
# Both load-driver.ps1 (kit copy) and game-watcher.ps1 (game copy) use this
# file, so the download logic exists exactly once.

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Invoke-WebRequest paces itself on the progress bar even when the window is
# hidden; everything here runs in a spawned headless process
$ProgressPreference = 'SilentlyContinue'

function Read-RemoteConfig([string]$path) {
    if (!(Test-Path -LiteralPath $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Get-ConfigValue($cfg, [string]$name, $fallback) {
    if ($cfg -and ($cfg.PSObject.Properties.Name -contains $name)) {
        $v = $cfg.$name
        if ($null -ne $v -and "$v" -ne '') { return $v }
    }
    return $fallback
}

function Get-FileSha256([string]$path) {
    # computed in .NET on purpose: Get-FileHash lives in a module, and a stripped
    # PSModulePath in a spawned hidden process makes it "not recognized"
    $sha = [Security.Cryptography.SHA256]::Create()
    $fs = $null
    try {
        $fs = [IO.File]::OpenRead($path)
        $bytes = $sha.ComputeHash($fs)
    } finally {
        if ($fs) { $fs.Dispose() }
        $sha.Dispose()
    }
    $sb = New-Object Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($b.ToString('X2')) }
    return $sb.ToString()
}

function Test-PeImage([string]$path) {
    $isPe = $false
    try {
        $fs = [IO.File]::OpenRead($path)
        $sig = New-Object byte[] 2
        $null = $fs.Read($sig, 0, 2)
        $fs.Close()
        $isPe = ($sig[0] -eq 0x4D -and $sig[1] -eq 0x5A)
    } catch { }
    return $isPe
}

function Get-StreamedFile([string]$url, [string]$path, [hashtable]$headers) {
    # streams straight to disk: Invoke-WebRequest buffers the whole body in
    # memory and crawls in a hidden process, a 11 MB dll took longer than the
    # whole game launch. HttpWebRequest + CopyTo never holds the payload.
    $req = [Net.HttpWebRequest]::Create($url)
    $req.Method = 'GET'
    $req.AllowAutoRedirect = $true
    $req.MaximumAutomaticRedirections = 8
    $req.Timeout = 30000
    $req.ReadWriteTimeout = 120000
    $req.KeepAlive = $false
    foreach ($k in $headers.Keys) {
        $v = [string]$headers[$k]
        if ($k -ieq 'User-Agent') { $req.UserAgent = $v }
        elseif ($k -ieq 'Accept') { $req.Accept = $v }
        elseif ($k -ieq 'Authorization') { $req.Headers['Authorization'] = $v }
        else { $req.Headers[$k] = $v }
    }

    $resp = $null
    $in = $null
    $out = $null
    $written = 0
    try {
        $resp = $req.GetResponse()
        $expect = $resp.ContentLength
        $in = $resp.GetResponseStream()
        $out = [IO.File]::Create($path)
        $buf = New-Object byte[] 131072
        while ($true) {
            $n = $in.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $out.Write($buf, 0, $n)
            $written += $n
        }
        $out.Flush()
    } finally {
        if ($out) { $out.Dispose() }
        if ($in) { $in.Dispose() }
        if ($resp) { $resp.Close() }
    }

    # a cut connection ends the stream early; a short body is a broken file
    if ($expect -gt 0 -and $written -ne $expect) {
        throw ('download truncated: got ' + $written + ' of ' + $expect + ' bytes')
    }
    return $written
}

function Invoke-Download([string]$url, [string]$dest, [hashtable]$headers, [string]$wantSha) {
    # returns { Changed, Hash, Size }; throws when the remote copy is unusable,
    # in which case the file already on disk is left exactly as it was
    $tmp = $dest + '.part'
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    $size = Get-StreamedFile -url $url -path $tmp -headers $headers
    if (!(Test-Path -LiteralPath $tmp)) { throw 'download produced no file' }
    if ($size -le 0) {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw 'downloaded file is empty'
    }

    # a .exe without an MZ header is an error page or a JSON envelope, not a payload
    if ((Split-Path -Leaf $dest) -match '(?i)\.exe$' -and !(Test-PeImage $tmp)) {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw 'downloaded file is not a PE image (no MZ header)'
    }

    $newHash = Get-FileSha256 $tmp
    $wantSha = $wantSha.Trim()
    if ($wantSha -and $newHash -ne $wantSha.ToUpper()) {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw ('sha256 mismatch: got ' + $newHash)
    }

    # same bytes as the copy on disk: nothing to update, target left untouched
    if (Test-Path -LiteralPath $dest) {
        $oldHash = Get-FileSha256 $dest
        if ($oldHash -eq $newHash) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            return [pscustomobject]@{ Changed = $false; Hash = $oldHash; Size = $size }
        }
    }

    # replace: a running exe keeps its image locked, so the caller stops it
    # first; the loop covers the moment the handle is still closing
    for ($i = 0; $i -lt 20; $i++) {
        try {
            if (Test-Path -LiteralPath $dest) {
                Remove-Item -LiteralPath $dest -Force -ErrorAction Stop
            }
            Move-Item -LiteralPath $tmp -Destination $dest -Force -ErrorAction Stop
            return [pscustomobject]@{ Changed = $true; Hash = $newHash; Size = $size }
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    throw 'cannot replace the target file (still locked)'
}

function Get-RemoteFile([string]$dest, $cfg) {
    $res = [pscustomobject]@{ Ok = $false; Changed = $false; Message = ''; Hash = '' }
    if (!$cfg) { $res.Message = 'no config'; return $res }

    $destDir = Split-Path -Parent $dest
    if ($destDir -and !(Test-Path -LiteralPath $destDir)) {
        New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    }

    $headers = @{ 'User-Agent' = 'VELQIR' }
    $token = [string](Get-ConfigValue $cfg 'token' '')
    if ($token) { $headers['Authorization'] = 'Bearer ' + $token }
    $wantSha = [string](Get-ConfigValue $cfg 'sha256' '')

    $dl = $null
    try {
        $direct = [string](Get-ConfigValue $cfg 'url' '')
        if ($direct) {
            $h = $headers.Clone()
            if ($direct -match '(?i)^https://api\.github\.com/') {
                # GitHub Contents API answers with a base64 JSON envelope by
                # default; this media type returns the raw file bytes
                $h['Accept'] = 'application/vnd.github.raw+json'
            }
            $dl = Invoke-Download -url $direct -dest $dest -headers $h -wantSha $wantSha
        } else {
            $owner = [string](Get-ConfigValue $cfg 'owner' '')
            $repo = [string](Get-ConfigValue $cfg 'repo' '')
            if (!$owner -or !$repo) {
                $res.Message = 'config has neither url nor owner/repo'
                return $res
            }
            $tag = [string](Get-ConfigValue $cfg 'tag' 'latest')
            $rel = 'latest'
            if ($tag -ne 'latest') { $rel = 'tags/' + $tag }
            $api = 'https://api.github.com/repos/' + $owner + '/' + $repo + '/releases/' + $rel

            $h = $headers.Clone()
            $h['Accept'] = 'application/vnd.github+json'
            $raw = (Invoke-WebRequest -Uri $api -Headers $h -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop).Content
            $release = $raw | ConvertFrom-Json

            $assetName = [string](Get-ConfigValue $cfg 'asset' '')
            $asset = $null
            if ($assetName) {
                $asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
            }
            if (!$asset) { $asset = $release.assets | Select-Object -First 1 }
            if (!$asset) { $res.Message = 'release has no assets'; return $res }

            $h2 = $headers.Clone()
            $h2['Accept'] = 'application/octet-stream'
            $dl = Invoke-Download -url $asset.url -dest $dest -headers $h2 -wantSha $wantSha
        }
    } catch {
        $res.Message = $_.Exception.Message
        return $res
    }

    $res.Ok = $true
    $res.Changed = [bool]$dl.Changed
    $res.Hash = [string]$dl.Hash
    $short = $res.Hash
    if ($short -and $short.Length -ge 12) { $short = $short.Substring(0, 12) }
    $res.Message = ('{0:N0} bytes, sha256 {1}' -f $dl.Size, $short)
    return $res
}

# ------------------------------------------------------------------ file list
# One config can carry several files: the exe that has to run right away plus
# whatever it needs next to it (dlls, data). "files" holds names or objects;
# a "{file}" placeholder in the top-level url is replaced by each name.

function Get-RemoteItems($cfg) {
    $items = @()
    $anyExplicitLaunch = $false
    $list = $null
    if ($cfg -and ($cfg.PSObject.Properties.Name -contains 'files')) { $list = $cfg.files }
    foreach ($e in @($list)) {
        if ($null -eq $e) { continue }
        $name = ''
        $url = ''
        $token = ''
        $sha = ''
        $launch = $null
        if ($e -is [string]) {
            $name = $e
        } else {
            $name = [string]$e.name
            if ($e.PSObject.Properties.Name -contains 'url') { $url = [string]$e.url }
            if ($e.PSObject.Properties.Name -contains 'token') { $token = [string]$e.token }
            if ($e.PSObject.Properties.Name -contains 'sha256') { $sha = [string]$e.sha256 }
            if ($e.PSObject.Properties.Name -contains 'launch') {
                $launch = [bool]$e.launch
                $anyExplicitLaunch = $true
            }
        }
        $name = $name.Trim()
        if (!$name) { continue }
        $items += [pscustomobject]@{ Name = $name; Url = $url; Token = $token; Sha256 = $sha; Launch = $launch }
    }
    if ($items.Count -eq 0) {
        $single = [string](Get-ConfigValue $cfg 'game_file' 'decompiler.exe')
        if (!$single) { return @() }
        $items += [pscustomobject]@{ Name = $single; Url = ''; Token = ''; Sha256 = ''; Launch = $null }
    }
    # only when nobody stated a preference: top-level switch plus the first exe
    if (!$anyExplicitLaunch -and [bool](Get-ConfigValue $cfg 'launch' $true)) {
        $first = @($items | Where-Object { $_.Name -match '(?i)\.exe$' })
        if ($first.Count -gt 0) { $first[0].Launch = $true }
    }
    foreach ($it in $items) { if ($null -eq $it.Launch) { $it.Launch = $false } }
    return $items
}

function Get-RemotePlan([string]$dir, $cfg) {
    $plan = @()
    foreach ($it in (Get-RemoteItems $cfg)) {
        $url = [string]$it.Url
        if (!$url) {
            $base = [string](Get-ConfigValue $cfg 'url' '')
            if ($base -match '\{file\}') { $url = $base.Replace('{file}', $it.Name) }
            else { $url = $base }
        }
        $token = [string]$it.Token
        if (!$token) { $token = [string](Get-ConfigValue $cfg 'token' '') }
        $sha = [string]$it.Sha256
        if (!$sha) { $sha = [string](Get-ConfigValue $cfg 'sha256' '') }
        $itemCfg = [pscustomobject]@{
            url = $url
            owner = [string](Get-ConfigValue $cfg 'owner' '')
            repo = [string](Get-ConfigValue $cfg 'repo' '')
            tag = [string](Get-ConfigValue $cfg 'tag' 'latest')
            asset = $it.Name
            token = $token
            sha256 = $sha
        }
        $plan += [pscustomobject]@{
            Name = $it.Name
            Path = (Join-Path $dir $it.Name)
            Launch = [bool]$it.Launch
            Config = $itemCfg
        }
    }
    return $plan
}
