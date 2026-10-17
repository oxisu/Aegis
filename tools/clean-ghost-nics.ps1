#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Aegis —— 幽灵网卡（Ghost NIC）只读盘点与清理工具。

.DESCRIPTION
    长期插拔安卓 USB 有线共享（RNDIS / Remote NDIS）会让 Windows 每次都生成
    全新的 NET_LUID，并在驱动存储里留下 Present=False、Status=Unknown 的
    设备实例。这些"幽灵网卡"会：
      · 污染感知层的拓扑快照（GetIfTable2 -IncludeHidden 可见）
      · 让 SHA-256 拓扑指纹在每次插拔后漂移，误触发"拓扑变更"告警
      · 残留 0.0.0.0/0 默认路由指向已消失的网卡

    本脚本只清理"真·幽灵"：PnP 状态非 OK 且 Present=False 的 Net 类设备。
    系统自带组件（WAN Miniport IKEv2/L2TP/PPTP/SSTP/PPPoE、Wi-Fi Direct、
    蓝牙 PAN、6to4、Teredo、IP-HTTPS、内核调试器）一律保留。

.PARAMETER Apply
    真正执行删除。默认只做只读盘点（等同 -WhatIf）。

.PARAMETER IncludeDriver
    额外用 pnputil /delete-driver 清掉对应的 oem*.inf 驱动存储条目。
    注意：会一并移除引用同一 INF 的其他设备实例，风险更高。

.PARAMETER BackupDir
    删除前设备清单备份目录，默认 .\evidence。

.EXAMPLE
    .\clean-ghost-nics.ps1                 # 只读盘点
    .\clean-ghost-nics.ps1 -Apply          # 确认无误后执行删除

.NOTES
    坑：本机环境里同时存在 Path 与 PATH 两个环境变量，.NET 的
    ProcessStartInfo.EnvironmentVariables（大小写不敏感字典）会抛
    "已添加项。字典中的关键字:'Path'所添加的关键字:'PATH'"，
    Start-Process / [Diagnostics.Process]::Start 都会失败。
    因此本脚本统一用 & 调用运算符直调 pnputil.exe，不经 Start-Process。
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch] $Apply,
    [switch] $IncludeDriver,
    # 留空则由脚本体自行推导（param 默认值里不能用 if 表达式）
    [string] $BackupDir
)

$ErrorActionPreference = 'Continue'

# 备份目录兜底：$PSScriptRoot 在个别调用方式下（powershell.exe -File 传相对路径）可能为空
if (-not $BackupDir) {
    if ($PSScriptRoot) { $BackupDir = Join-Path $PSScriptRoot '..\evidence' }
    else               { $BackupDir = '.\evidence' }
}

# ── 保护名单：命中任一关键字的设备永不删除 ───────────────────────────────
$ProtectedPatterns = @(
    'WAN Miniport', 'Wi-Fi Direct', 'Bluetooth', '6to4', 'Teredo',
    'IP-HTTPS', 'Kernel Debug', 'Microsoft KM-Test', 'Hyper-V',
    'VirtualBox', 'VMware', 'TAP-Windows', 'WireGuard', 'OpenVPN',
    'Loopback', 'ISATAP', 'RAS Async'
)

function Test-Protected {
    param([string] $Name)
    foreach ($p in $ProtectedPatterns) {
        if ($Name -match [regex]::Escape($p)) { return $true }
    }
    return $false
}

# ── 1. 只读盘点 ─────────────────────────────────────────────────────────
Write-Host '══════ 1. 幽灵网卡盘点 ══════' -ForegroundColor Cyan

$ghosts = @(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -ne 'OK' -and $_.Present -eq $false })

if ($ghosts.Count -eq 0) {
    Write-Host '未发现幽灵网卡（PnP Net 类全部 OK）—— 无需清理。' -ForegroundColor Green
} else {
    Write-Host "发现 $($ghosts.Count) 个幽灵候选：" -ForegroundColor Yellow
    $ghosts | ForEach-Object {
        $bad = Test-Protected $_.FriendlyName
        $flag = if ($bad) { '[保护·跳过]' } else { '[待清理]' }
        Write-Host ("  {0} {1,-12} {2}" -f $flag, $_.Status, $_.FriendlyName)
        Write-Host ("              {0}" -f $_.InstanceId) -ForegroundColor DarkGray
    }
}

# ── 2. 默认路由体检 ─────────────────────────────────────────────────────
Write-Host ''
Write-Host '══════ 2. 默认路由体检 ══════' -ForegroundColor Cyan
$upIndex = @{}
Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    ForEach-Object { $upIndex[[string]$_.InterfaceIndex] = $_.Status }

$staleRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object { $upIndex[[string]$_.InterfaceIndex] -ne 'Up' })

Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object { $_.RouteMetric + $_.InterfaceMetric } |
    ForEach-Object {
        $st = $upIndex[[string]$_.InterfaceIndex]; if (-not $st) { $st = '<无网卡>' }
        $mark = if ($st -eq 'Up') { ' ' } else { '✗' }
        Write-Host ("  {0} {1,-14} -> {2,-16} metric={3,-5} nic={4}" -f
            $mark, $_.InterfaceAlias, $_.NextHop,
            ($_.RouteMetric + $_.InterfaceMetric), $st)
    }
if ($staleRoutes.Count -eq 0) {
    Write-Host '  无失效默认路由。' -ForegroundColor Green
} else {
    Write-Host "  ⚠ 存在 $($staleRoutes.Count) 条指向非 Up 网卡的默认路由，建议用 Remove-NetRoute 清理。" -ForegroundColor Yellow
}

# ── 3. 执行清理 ─────────────────────────────────────────────────────────
$targets = @($ghosts | Where-Object { -not (Test-Protected $_.FriendlyName) })

if (-not $Apply) {
    Write-Host ''
    Write-Host '══════ 3. 清理 ══════' -ForegroundColor Cyan
    Write-Host "当前为只读盘点模式。确认无误后加 -Apply 执行删除（目标 $($targets.Count) 个）。" -ForegroundColor Cyan
    return
}

if ($targets.Count -eq 0) {
    Write-Host ''
    Write-Host '没有可清理的目标，退出。' -ForegroundColor Green
    return
}

# 备份
if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$bakFile = Join-Path $BackupDir "pnp-net-before-$stamp.txt"
$lines  = @("# Aegis 幽灵网卡清理前备份  $stamp")
Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Sort-Object Status, FriendlyName |
    ForEach-Object { $lines += ("{0,-10} | {1,-6} | {2}  # {3}" -f $_.Status, $_.Present, $_.InstanceId, $_.FriendlyName) }
$lines += ''; $lines += '# 默认路由快照'
Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    ForEach-Object { $lines += ("ifIndex={0} alias={1} nexthop={2} metric={3}" -f $_.InterfaceIndex, $_.InterfaceAlias, $_.NextHop, ($_.RouteMetric + $_.InterfaceMetric)) }
Set-Content -Path $bakFile -Value $lines -Encoding UTF8
Write-Host ''
Write-Host "备份已写入: $bakFile" -ForegroundColor DarkGray

Write-Host ''
Write-Host '══════ 3. 清理 ══════' -ForegroundColor Cyan
foreach ($g in $targets) {
    $id = $g.InstanceId
    if ($PSCmdlet.ShouldProcess($id, '移除幽灵网卡设备')) {
        Write-Host "  删除: $($g.FriendlyName)"
        Write-Host "        $id" -ForegroundColor DarkGray
        & pnputil.exe /remove-device "$id" 2>&1 | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
        Write-Host "        LASTEXITCODE=$LASTEXITCODE"
    }
}

# 可选：清驱动存储
if ($IncludeDriver) {
    Write-Host ''
    Write-Host '══════ 4. 清理驱动存储 (oem*.inf) ══════' -ForegroundColor Cyan
    & pnputil.exe /enum-drivers 2>&1 |
        Select-String -Pattern 'Remote NDIS|RNDIS' -Context 6, 0 |
        ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    Write-Host '  以上为 RNDIS 相关驱动包。请人工核对 Published Name 后执行：' -ForegroundColor Yellow
    Write-Host '    pnputil.exe /delete-driver oemNN.inf /uninstall /force' -ForegroundColor Yellow
    Write-Host '  （本脚本不自动执行，避免误删同 INF 的其它实例）' -ForegroundColor Yellow
}

# ── 4. 复查 ─────────────────────────────────────────────────────────────
Start-Sleep -Seconds 3
Write-Host ''
Write-Host '══════ 5. 复查 ══════' -ForegroundColor Cyan
$left = @(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'OK' })
if ($left.Count -eq 0) { Write-Host '幽灵设备已清零。' -ForegroundColor Green }
else { $left | ForEach-Object { Write-Host ("  残留: {0} | {1}" -f $_.Status, $_.InstanceId) -ForegroundColor Yellow } }

Write-Host '在用的 Up 网卡：'
Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } |
    ForEach-Object { Write-Host ("  ifIndex={0,-4} {1} / {2}" -f $_.ifIndex, $_.Name, $_.InterfaceDescription) }
