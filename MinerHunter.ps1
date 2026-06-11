<#
 MinerHunter-DOIZZP
 Diagnostico seguro para suspeita de miner/malware evasivo.
 Nao deleta arquivos automaticamente. Gera relatorios e permite quarentena controlada.
#>

$BaseDir = "C:\MinerHunter-DOIZZP"
$ReportDir = Join-Path $BaseDir "Reports"
$QuarantineDir = Join-Path $BaseDir "Quarantine"
$Date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
New-Item -ItemType Directory -Force -Path $QuarantineDir | Out-Null

$ReportTxt = Join-Path $ReportDir "MinerHunter_Report_$Date.txt"
$ProcCsv   = Join-Path $ReportDir "Processes_$Date.csv"
$StartCsv  = Join-Path $ReportDir "Startup_$Date.csv"
$TasksTxt  = Join-Path $ReportDir "ScheduledTasks_$Date.txt"
$SvcCsv    = Join-Path $ReportDir "Services_$Date.csv"
$NetCsv    = Join-Path $ReportDir "Network_$Date.csv"
$SusCsv    = Join-Path $ReportDir "Suspects_$Date.csv"

function Write-Log {
    param([string]$Text)
    $Line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $Text
    Add-Content -Path $ReportTxt -Value $Line
    Write-Host $Line
}

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ProcessInventory {
    Write-Log "Coletando processos com CPU, RAM, caminho, empresa e assinatura digital..."

    $list = Get-Process | ForEach-Object {
        $proc = $_
        $path = $null
        $signature = "N/A"
        $company = "N/A"
        $description = "N/A"
        $product = "N/A"

        try { $path = $proc.Path } catch {}

        if ($path -and (Test-Path $path)) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $path
                $signature = $sig.Status
            } catch {}

            try {
                $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
                $company = $info.CompanyName
                $description = $info.FileDescription
                $product = $info.ProductName
            } catch {}
        }

        [PSCustomObject]@{
            ProcessName = $proc.ProcessName
            PID         = $proc.Id
            CPU_Total   = $proc.CPU
            RAM_MB      = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            Path        = $path
            Signature   = $signature
            Company     = $company
            Product     = $product
            Description = $description
        }
    }

    $list | Sort-Object CPU_Total -Descending | Export-Csv -Path $ProcCsv -NoTypeInformation -Encoding UTF8
    return $list
}

function Get-StartupInventory {
    Write-Log "Coletando itens de inicializacao..."
    $items = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
    $items | Export-Csv -Path $StartCsv -NoTypeInformation -Encoding UTF8
    return $items
}

function Get-ServiceInventory {
    Write-Log "Coletando servicos..."
    $services = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName
    $services | Export-Csv -Path $SvcCsv -NoTypeInformation -Encoding UTF8
    return $services
}

function Get-TaskInventory {
    Write-Log "Coletando tarefas agendadas fora da pasta Microsoft..."
    Get-ScheduledTask |
        Where-Object { $_.TaskPath -notlike "\Microsoft*" } |
        Select-Object TaskName, TaskPath, State |
        Format-Table -AutoSize |
        Out-String |
        Set-Content -Path $TasksTxt
}

function Get-NetworkInventory {
    Write-Log "Coletando conexoes de rede ativas com PID..."
    try {
        $net = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        $net | Export-Csv -Path $NetCsv -NoTypeInformation -Encoding UTF8
        return $net
    } catch {
        Write-Log "Nao foi possivel coletar conexoes de rede via Get-NetTCPConnection."
        return @()
    }
}

function Find-SuspiciousProcesses {
    param([array]$Processes)

    $SuspiciousPaths = @(
        "\AppData\Roaming\",
        "\AppData\Local\Temp\",
        "\AppData\LocalLow\",
        "\ProgramData\",
        "\Windows\Temp\",
        "\Users\Public\",
        "\Microsoft\Windows\Start Menu\Programs\Startup\"
    )

    $SuspiciousNames = @(
        "xmrig", "miner", "xmr", "monero", "ethminer", "nanominer", "lolminer",
        "nbminer", "phoenixminer", "cryptonight", "nicehash", "cpuminer", "minerd"
    )

    $SystemSafe = @(
        "C:\Windows\System32\",
        "C:\Windows\SysWOW64\",
        "C:\Program Files\Windows Defender\",
        "C:\Program Files\Microsoft Defender\"
    )

    $suspects = $Processes | Where-Object {
        $p = $_
        $path = [string]$p.Path
        $name = [string]$p.ProcessName

        $isSafeSystem = $false
        foreach ($safe in $SystemSafe) {
            if ($path.StartsWith($safe, [System.StringComparison]::OrdinalIgnoreCase)) {
                $isSafeSystem = $true
            }
        }

        $nameHit = $false
        foreach ($n in $SuspiciousNames) {
            if ($name -like "*$n*" -or $path -like "*$n*") { $nameHit = $true }
        }

        $pathHit = $false
        foreach ($sp in $SuspiciousPaths) {
            if ($path -like "*$sp*") { $pathHit = $true }
        }

        (($p.Signature -eq "NotSigned") -or $pathHit -or $nameHit) -and -not $isSafeSystem
    }

    $suspects | Sort-Object CPU_Total -Descending | Export-Csv -Path $SusCsv -NoTypeInformation -Encoding UTF8
    return $suspects
}

function Start-Diagnostic {
    Clear-Host
    Write-Log "===== MINERHUNTER DOIZZP - DIAGNOSTICO INICIADO ====="
    Write-Log "Pasta base: $BaseDir"
    Write-Log "Relatorios: $ReportDir"
    Write-Log "Quarentena: $QuarantineDir"
    Write-Log "Modo seguro: nenhuma exclusao automatica sera feita."

    if (-not (Test-IsAdmin)) {
        Write-Log "AVISO: execute como Administrador para coletar mais detalhes."
    }

    $processes = Get-ProcessInventory
    Get-StartupInventory | Out-Null
    Get-ServiceInventory | Out-Null
    Get-TaskInventory
    Get-NetworkInventory | Out-Null

    Write-Log "Registrando top 20 processos por CPU acumulada..."
    $processes |
        Sort-Object CPU_Total -Descending |
        Select-Object -First 20 |
        Format-Table ProcessName, PID, CPU_Total, RAM_MB, Signature, Path -AutoSize |
        Out-String |
        Add-Content -Path $ReportTxt

    Write-Log "Procurando padroes suspeitos..."
    $suspects = Find-SuspiciousProcesses -Processes $processes

    Write-Log "===== POSSIVEIS SUSPEITOS ====="
    if ($suspects.Count -gt 0) {
        $suspects |
            Sort-Object CPU_Total -Descending |
            Format-Table ProcessName, PID, CPU_Total, RAM_MB, Signature, Path -AutoSize |
            Out-String |
            Add-Content -Path $ReportTxt
        Write-Log "Suspeitos encontrados. Confira: $SusCsv"
    } else {
        Write-Log "Nenhum suspeito obvio encontrado pelos filtros iniciais."
    }

    Write-Log "===== PROXIMOS PASSOS ====="
    Write-Log "1. Nao delete nada ainda."
    Write-Log "2. Verifique Suspects CSV e caminhos estranhos."
    Write-Log "3. Use Autoruns para desabilitar inicializacao suspeita."
    Write-Log "4. Rode Microsoft Defender Offline em caso forte de infeccao."
    Write-Log "===== DIAGNOSTICO FINALIZADO ====="

    Write-Host ""
    Write-Host "Relatorio criado em: $ReportTxt" -ForegroundColor Cyan
    Write-Host "Suspeitos, se houver: $SusCsv" -ForegroundColor Yellow
}

function Start-QuarantineMenu {
    Clear-Host
    Write-Host "===== MINERHUNTER DOIZZP - QUARENTENA CONTROLADA =====" -ForegroundColor Magenta
    Write-Host "Use isso apenas apos confirmar que o arquivo e suspeito."
    Write-Host "Nao coloque arquivos do Windows, drivers, Steam, Discord, AMD/NVIDIA ou anticheats sem certeza."
    Write-Host ""

    $file = Read-Host "Cole o caminho completo do arquivo suspeito"

    if (-not (Test-Path $file)) {
        Write-Host "Arquivo nao encontrado." -ForegroundColor Red
        Pause
        return
    }

    $confirm = Read-Host "Mover para quarentena? Digite SIM para confirmar"
    if ($confirm -ne "SIM") {
        Write-Host "Cancelado."
        Pause
        return
    }

    try {
        $destName = "{0}_{1}" -f (Get-Date -Format "yyyyMMdd_HHmmss"), (Split-Path $file -Leaf)
        $dest = Join-Path $QuarantineDir $destName
        Move-Item -Path $file -Destination $dest -Force
        Write-Host "Arquivo movido para: $dest" -ForegroundColor Green
    } catch {
        Write-Host "Falha ao mover arquivo: $($_.Exception.Message)" -ForegroundColor Red
    }
    Pause
}

function Show-Menu {
    do {
        Clear-Host
        Write-Host "" 
        Write-Host "  __  __ _                 _   _             _            " -ForegroundColor Magenta
        Write-Host " |  \/  (_)_ __   ___ _ __| | | |_   _ _ __ | |_ ___ _ __ " -ForegroundColor Magenta
        Write-Host " | |\/| | | '_ \ / _ \ '__| |_| | | | | '_ \| __/ _ \ '__|" -ForegroundColor Magenta
        Write-Host " | |  | | | | | |  __/ |  |  _  | |_| | | | | ||  __/ |   " -ForegroundColor Magenta
        Write-Host " |_|  |_|_|_| |_|\___|_|  |_| |_|\__,_|_| |_|\__\___|_|   " -ForegroundColor Magenta
        Write-Host ""
        Write-Host "        MinerHunter-DOIZZP - Diagnostico Seguro" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[1] Diagnostico completo"
        Write-Host "[2] Mover arquivo suspeito para quarentena"
        Write-Host "[3] Abrir pasta de relatorios"
        Write-Host "[4] Abrir pasta de quarentena"
        Write-Host "[5] Abrir Windows Security"
        Write-Host "[0] Sair"
        Write-Host ""
        $choice = Read-Host "Escolha uma opcao"

        switch ($choice) {
            "1" { Start-Diagnostic; Pause }
            "2" { Start-QuarantineMenu }
            "3" { Start-Process explorer.exe $ReportDir }
            "4" { Start-Process explorer.exe $QuarantineDir }
            "5" { Start-Process "windowsdefender:" }
            "0" { break }
            default { Write-Host "Opcao invalida." -ForegroundColor Red; Start-Sleep -Seconds 1 }
        }
    } while ($choice -ne "0")
}

Show-Menu
