# ============================================================
# WinDFIR Audit — saída na pasta atual do PowerShell ($PWD)
# Abrir PowerShell COMO ADMINISTRADOR e colar este bloco.
# ============================================================

# --- CONFIGURAÇÃO ---
$BaseDir   = $PWD.Path
$OutputDir = Join-Path $BaseDir "WinDFIR_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$MaxEvents = 50000
$HoursBack = 24
# --------------------

# Verificação de Administrador
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Este script requer Administrador. Abre PowerShell como Administrador." -ForegroundColor Red
    return
}

$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$StartTime = Get-Date
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  WinDFIR Audit — Início: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host "  Base (PWD): $BaseDir" -ForegroundColor Cyan
Write-Host "  Output:     $OutputDir" -ForegroundColor Cyan
Write-Host "  Janela: últimas $HoursBack horas | MaxEvents: $MaxEvents" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# ---------------------------------------------------------
# FUNÇÕES AUXILIARES
# ---------------------------------------------------------
function Write-Section { param([string]$Title) Write-Host "`n[*] $Title" -ForegroundColor Cyan }
function Write-Warn    { param([string]$Message) Write-Host "    [!] $Message" -ForegroundColor Yellow }

function Export-Json {
    param($Data, [string]$Filename)
    if ($null -eq $Data -or @($Data).Count -eq 0) {
        Write-Host "    -> $Filename (vazio, ignorado)" -ForegroundColor DarkGray; return
    }
    $Data | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $OutputDir $Filename) -Encoding UTF8
    Write-Host "    -> $Filename ($(@($Data).Count) registos)" -ForegroundColor DarkGray
}

function Export-CsvSafe {
    param($Data, [string]$Filename)
    if ($null -eq $Data -or @($Data).Count -eq 0) {
        Write-Host "    -> $Filename (vazio, ignorado)" -ForegroundColor DarkGray; return
    }
    $Data | Export-Csv -Path (Join-Path $OutputDir $Filename) -NoTypeInformation -Encoding UTF8
    Write-Host "    -> $Filename ($(@($Data).Count) registos)" -ForegroundColor DarkGray
}

function Get-EventData {
    param($Event)
    $xml = [xml]$Event.ToXml()
    $data = @{}
    $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
    return $data
}

# ---------------------------------------------------------
# 1. PROCESSOS
# ---------------------------------------------------------
Write-Section "Processos ativos"
$processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    $proc = $_
    $owner = try { $proc.GetOwner() } catch { $null }
    [PSCustomObject]@{
        PID            = $proc.ProcessId
        PPID           = $proc.ParentProcessId
        Name           = $proc.Name
        ExecutablePath = $proc.ExecutablePath
        CommandLine    = $proc.CommandLine
        User           = if ($owner) { "$($owner.Domain)\$($owner.User)" } else { "N/A" }
        CreationDate   = $proc.CreationDate
    }
}
$suspiciousProcs = $processes | Where-Object {
    $_.ExecutablePath -and
    $_.ExecutablePath -notlike 'C:\Windows\*' -and
    $_.ExecutablePath -notlike 'C:\Program Files\*' -and
    $_.ExecutablePath -notlike 'C:\Program Files (x86)\*'
}
Export-CsvSafe -Data $processes -Filename "processes_all.csv"
Export-CsvSafe -Data $suspiciousProcs -Filename "processes_suspicious_paths.csv"

# ---------------------------------------------------------
# 2. REDE
# ---------------------------------------------------------
Write-Section "Conexões de rede"
$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
    $_.State -eq 'Established' -or $_.State -eq 'Listen'
} | ForEach-Object {
    $conn = $_
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress  = $conn.LocalAddress; LocalPort = $conn.LocalPort
        RemoteAddress = $conn.RemoteAddress; RemotePort = $conn.RemotePort
        State         = $conn.State; OwningProcess = $conn.OwningProcess
        ProcessName   = if ($proc) { $proc.ProcessName } else { "N/A" }
        ProcessPath   = if ($proc) { $proc.Path } else { "N/A" }
    }
}
Export-CsvSafe -Data $connections -Filename "network_connections.csv"

try {
    $dnsCache = Get-DnsClientCache -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{ Entry=$_.Entry; RecordName=$_.RecordName; RecordType=$_.RecordType; Data=$_.Data; TimeToLive=$_.TimeToLive }
    }
    Export-CsvSafe -Data $dnsCache -Filename "dns_cache.csv"
} catch { Write-Warn "Get-DnsClientCache indisponível." }

# ---------------------------------------------------------
# 3. LOGINS / SESSÕES
# ---------------------------------------------------------
Write-Section "Sessões e logins"
$sessions = try {
    Get-CimInstance Win32_LogonSession -ErrorAction Stop | Where-Object { $_.LogonType -in 2,10 } | ForEach-Object {
        $users = Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_Account -ErrorAction SilentlyContinue
        [PSCustomObject]@{ LogonId=$_.LogonId; LogonType=$_.LogonType; StartTime=$_.StartTime; Users=($users.Name -join ', ') }
    }
} catch { $null }
Export-CsvSafe -Data $sessions -Filename "sessions_active.csv"

Write-Host "    A extrair eventos de logon ($HoursBack h)..." -ForegroundColor DarkGray
$logonEvents = Get-WinEvent -MaxEvents $MaxEvents -FilterHashtable @{
    LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddHours(-$HoursBack)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $d = Get-EventData -Event $_
    [PSCustomObject]@{
        TimeCreated=$_.TimeCreated; EventId=$_.Id
        EventType=if ($_.Id -eq 4624) { "LogonSuccess" } else { "LogonFailure" }
        TargetUser=$d['TargetUserName']; TargetDomain=$d['TargetDomainName']
        LogonType=$d['LogonType']; SourceIP=$d['IpAddress']
        Workstation=$d['WorkstationName']; ProcessName=$d['ProcessName']
    }
}
if ($logonEvents) {
    Export-CsvSafe -Data $logonEvents -Filename "logons_${HoursBack}h.csv"
    $remoteLogons = $logonEvents | Where-Object { $_.LogonType -in @('3','10') }
    if ($remoteLogons) { Export-CsvSafe -Data $remoteLogons -Filename "logons_remote_${HoursBack}h.csv" }
}

# ---------------------------------------------------------
# 4. POWERSHELL
# ---------------------------------------------------------
Write-Section "Atividade PowerShell"
$psHistoryFiles = @()
$usersRoot = "C:\Users"
if (Test-Path $usersRoot) {
    $psHistoryFiles += Get-ChildItem -Path $usersRoot -Filter "ConsoleHost_history.txt" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*PSReadLine*" }
}
$currentHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $currentHistory) { $psHistoryFiles += Get-Item $currentHistory }

$allHistory = foreach ($hf in ($psHistoryFiles | Sort-Object FullName -Unique)) {
    [PSCustomObject]@{ User=($hf.FullName -split '\\')[2]; FilePath=$hf.FullName; Lines=@(Get-Content $hf.FullName -ErrorAction SilentlyContinue) }
}
if ($allHistory) {
    foreach ($h in $allHistory) {
        $safeName = "powershell_history_$($h.User).txt"
        $h.Lines | Out-File -FilePath (Join-Path $OutputDir $safeName) -Encoding UTF8
        Write-Host "    -> $safeName ($($h.Lines.Count) linhas)" -ForegroundColor DarkGray
    }
} else { Write-Warn "Nenhum histórico PSReadLine encontrado." }

Write-Host "    A extrair Script Blocks suspeitos (4104, ${HoursBack}h)..." -ForegroundColor DarkGray
$suspiciousPatterns = @(
    'Invoke-Expression','\bIEX\b','DownloadString','DownloadFile','FromBase64String',
    'EncodedCommand','Bypass','WindowStyle\s+Hidden','WebClient','Start-BitsTransfer',
    'Add-Type','Reflection\.Assembly','\[Convert\]::FromBase64','Net\.Sockets','TcpClient',
    'Net\.WebClient','Invoke-WebRequest.*-UseBasicParsing','Invoke-RestMethod',
    'AmsiUtils','amsiInitFailed','System\.Management\.Automation','Set-MpPreference',
    'Add-MpPreference','MpCmdRun'
) -join '|'

$scriptBlocks = Get-WinEvent -MaxEvents $MaxEvents -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddHours(-$HoursBack)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $d = Get-EventData -Event $_
    $scriptText = $d['ScriptBlockText']
    if ($scriptText -match $suspiciousPatterns) {
        [PSCustomObject]@{ TimeCreated=$_.TimeCreated; ScriptBlockId=$d['ScriptBlockId']; ScriptText=$scriptText.Substring(0,[Math]::Min(3000,$scriptText.Length)) }
    }
}
if ($scriptBlocks) { Export-Json -Data $scriptBlocks -Filename "powershell_suspicious_4104.json" }
else { Write-Host "    Nenhum script block suspeito encontrado." -ForegroundColor DarkGray }

# ---------------------------------------------------------
# 5. LOGS DE SEGURANÇA CRÍTICOS
# ---------------------------------------------------------
Write-Section "Eventos de segurança críticos (${HoursBack}h)"
$criticalEvents = @()
$eventQueries = @(
    @{ Log='Security'; Id=4688; Type='ProcessCreated' },
    @{ Log='Security'; Id=4697; Type='ServiceInstalled' },
    @{ Log='System';   Id=7045; Type='ServiceInstalled' },
    @{ Log='Security'; Id=4698; Type='ScheduledTaskCreated' },
    @{ Log='Security'; Id=4720; Type='UserAccountCreated' },
    @{ Log='Security'; Id=4728; Type='GroupMemberAdded' },
    @{ Log='Security'; Id=4732; Type='GroupMemberAddedLocal' }
)
foreach ($q in $eventQueries) {
    $events = Get-WinEvent -MaxEvents $MaxEvents -FilterHashtable @{ LogName=$q.Log; Id=$q.Id; StartTime=(Get-Date).AddHours(-$HoursBack) } -ErrorAction SilentlyContinue | ForEach-Object {
        $d = Get-EventData -Event $_
        [PSCustomObject]@{
            TimeCreated=$_.TimeCreated; EventId=$_.Id; EventType=$q.Type
            Details=($d.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
        }
    }
    if ($events) { $criticalEvents += $events }
}
if ($criticalEvents) { Export-CsvSafe -Data $criticalEvents -Filename "security_critical_events_${HoursBack}h.csv" }
else { Write-Warn "Nenhum evento crítico (auditoria pode não estar habilitada)." }

# ---------------------------------------------------------
# 6. PERSISTÊNCIA
# ---------------------------------------------------------
Write-Section "Persistência"
$persistence = @()
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $persistence += [PSCustomObject]@{ Type="RegistryRun"; Name=$_.Name; Value=$_.Value; Path=$rp }
        }
    }
}
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object {
    $action = $_.Actions | Select-Object -First 1
    $persistence += [PSCustomObject]@{
        Type="ScheduledTask"; Name=$_.TaskName
        Value=if ($action) { $action.Execute } else { "N/A" }
        Path=if ($action) { $action.Arguments } else { "N/A" }
    }
}
$allServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Name=$_.Name; DisplayName=$_.DisplayName; PathName=$_.PathName
        StartMode=$_.StartMode; State=$_.State; StartName=$_.StartName
        SuspiciousPath=[bool]($_.PathName -and $_.PathName -notlike 'C:\Windows\*')
    }
}
$persistence += $allServices | ForEach-Object { [PSCustomObject]@{ Type="Service"; Name=$_.Name; Value=$_.PathName; Path=$_.StartMode } }
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)
foreach ($sp in $startupPaths) {
    if (Test-Path $sp) {
        Get-ChildItem -Path $sp -File -ErrorAction SilentlyContinue | ForEach-Object {
            $persistence += [PSCustomObject]@{ Type="StartupFolder"; Name=$_.Name; Value=$_.FullName; Path=$sp }
        }
    }
}
try {
    $wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction Stop
    foreach ($c in $wmiConsumers) {
        $persistence += [PSCustomObject]@{ Type="WMI-Consumer"; Name=$c.Name; Value=$c.CommandLineTemplate; Path=$c.ExecutablePath }
    }
} catch { Write-Warn "WMI Consumers inacessíveis." }

Export-CsvSafe -Data $persistence -Filename "persistence_summary.csv"
Export-CsvSafe -Data $allServices -Filename "services_all.csv"
Export-CsvSafe -Data ($allServices | Where-Object SuspiciousPath) -Filename "services_suspicious_paths.csv"

# ---------------------------------------------------------
# 7. FIREWALL
# ---------------------------------------------------------
Write-Section "Firewall"
Write-Host "    A extrair regras de firewall ativas..." -ForegroundColor DarkGray
$firewallRules = Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -notmatch '^Microsoft|^@|^Core Networking|^Delivery Optimization|^File and Printer Sharing' } |
    ForEach-Object {
        $rule = $_
        $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $appFilter  = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        $addrFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            DisplayName=$rule.DisplayName; Direction=$rule.Direction; Action=$rule.Action
            Profile=$rule.Profile; Enabled=$rule.Enabled; Protocol=$portFilter.Protocol
            LocalPort=$portFilter.LocalPort; RemotePort=$portFilter.RemotePort
            RemoteAddress=$addrFilter.RemoteAddress; Program=$appFilter.Program
            PolicySource=$rule.PolicyStoreSourceType
        }
    }
Export-CsvSafe -Data $firewallRules -Filename "firewall_rules_active.csv"

Write-Host "    A extrair histórico de alterações de regras (${HoursBack}h)..." -ForegroundColor DarkGray
$fwLog = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
$fwChanges = Get-WinEvent -MaxEvents $MaxEvents -FilterHashtable @{ LogName=$fwLog; Id=2004,2005,2006; StartTime=(Get-Date).AddHours(-$HoursBack) } -ErrorAction SilentlyContinue | ForEach-Object {
    $d = Get-EventData -Event $_
    [PSCustomObject]@{
        TimeCreated=$_.TimeCreated; EventId=$_.Id
        Action=switch ($_.Id) { 2004 { "RuleAdded" } 2005 { "RuleModified" } 2006 { "RuleDeleted" } }
        RuleName=$d['RuleName']; RuleId=$d['RuleId']; Direction=$d['Direction']
        Profiles=$d['Profiles']; Protocol=$d['Protocol']; LocalPorts=$d['LocalPorts']
        RemotePorts=$d['RemotePorts']; RemoteAddress=$d['RemoteAddresses']
        Program=$d['ModifyingApplication']; User=$d['ModifyingUser']
    }
}
if ($fwChanges) { Export-CsvSafe -Data $fwChanges -Filename "firewall_rule_changes_${HoursBack}h.csv" }
else { Write-Warn "Nenhuma alteração de regra (log pode estar desabilitado)."; Write-Warn "Verificar: wevtutil gl `"$fwLog`"" }

# ---------------------------------------------------------
# RESUMO FINAL
# ---------------------------------------------------------
$EndTime = Get-Date
$Duration = $EndTime - $StartTime
$files = Get-ChildItem -Path $OutputDir -File -ErrorAction SilentlyContinue

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  AUDITORIA CONCLUÍDA" -ForegroundColor Green
Write-Host "  Duração: $([Math]::Round($Duration.TotalSeconds, 1))s" -ForegroundColor Green
Write-Host "  Ficheiros gerados: $($files.Count)" -ForegroundColor Green
Write-Host "  Diretório: $OutputDir" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green

Write-Host "`n[!] PRIORIDADE DE ANÁLISE:" -ForegroundColor Yellow
Write-Host "    1. processes_suspicious_paths.csv       — binários fora de locais padrão"
Write-Host "    2. logons_remote_${HoursBack}h.csv              — logons rede (3) e RDP (10)"
Write-Host "    3. powershell_suspicious_4104.json      — script blocks ofuscados"
Write-Host "    4. security_critical_events_${HoursBack}h.csv   — serviços/tarefas/contas/grupos"
Write-Host "    5. services_suspicious_paths.csv        — serviços fora de System32"
Write-Host "    6. firewall_rule_changes_${HoursBack}h.csv      — regras adicionadas/modificadas"
Write-Host "    7. persistence_summary.csv              — todos os mecanismos de persistência"
Write-Host "    8. dns_cache.csv                        — domínios resolvidos recentemente"
Write-Host "    9. network_connections.csv              — conexões ativas com processo"
