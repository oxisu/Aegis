# InterBoot 开发构建入口（Windows）—— MSVC 路线专用
#
# ⚠ 注意：当前仓库默认走的是 **gnu/MinGW 路线**（见 rust-toolchain.toml），
#   因为本机尚未装好 MSVC 生成工具。等 MSVC 装好后，
#   把 rust-toolchain.toml 的 channel 改为 stable-x86_64-pc-windows-msvc，
#   再用本脚本构建即可。
#
# 作用：一次性把本机两个已知环境陷阱处理干净，再调用 cargo：
#   1) GNU link.exe 抢占 —— Git Bash 会在 PATH 里放 coreutils 的 link.exe，
#      rustc 调错程序会报 "link: extra operand ... Try 'link --help'"。
#      本脚本把 MSVC 的 bin 放到 PATH 最前，抢回 link.exe 这个名字。
#   2) 失效系统代理 —— Internet 选项若残留已停止运行的本地代理，
#      cargo 拉依赖会卡在 "Could not connect to server over proxy 127.0.0.1"。
#      本脚本清空代理环境变量，直连拉包。
#
# 用法：
#   .\tools\dev-env.ps1 check -p ob-sense --all-targets
#   .\tools\dev-env.ps1 run   -p ob-sense --example dry_run
#   .\tools\dev-env.ps1 fmt
#
# 自定义工具链位置：
#   .\tools\dev-env.ps1 -VsRoot D:\Dev\VSBuildTools -CargoHome D:\Dev\Rust\.cargo check

[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$VsRoot    = 'D:\Dev\VSBuildTools',
    [string]$CargoHome = 'D:\Dev\Rust\.cargo',
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArgs
)

$ErrorActionPreference = 'Stop'

function Test-Directory($p) { Test-Path -LiteralPath $p -PathType Container }

# ── 1. 定位 MSVC 工具集 ────────────────────────────────────────────
if (-not (Test-Directory $VsRoot)) {
    Write-Error "找不到 VS Build Tools 目录: $VsRoot`n请用 -VsRoot 指定实际安装位置。"
}

$msvcRoot = Join-Path $VsRoot 'VC\Tools\MSVC'
if (-not (Test-Directory $msvcRoot)) {
    Write-Error "MSVC 工具集未安装: $msvcRoot`n请先安装 Build Tools 的 C++ 工作负载。"
}

$msvc = Get-ChildItem -LiteralPath $msvcRoot -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
if (-not $msvc) { Write-Error "MSVC 工具集目录为空: $msvcRoot" }

$hostBin = Join-Path $msvc.FullName 'bin\Hostx64\x64'
if (-not (Test-Directory $hostBin)) {
    Write-Error "找不到 x64 宿主二进制目录: $hostBin"
}

# ── 2. 定位 Windows SDK（提供 kernel32.lib 等系统库）────────────────
$sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$sdkVersion = $null
if (Test-Directory (Join-Path $sdkRoot 'Lib')) {
    $sdk = Get-ChildItem -LiteralPath (Join-Path $sdkRoot 'Lib') -Directory -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -match '^10\.' } | Sort-Object Name -Descending | Select-Object -First 1
    if ($sdk) { $sdkVersion = $sdk.Name }
}

# ── 3. 组装环境 ────────────────────────────────────────────────────
# MSVC bin 置顶，确保 rustc 找到的是微软的 link.exe 而不是 coreutils 的
$env:PATH = "$hostBin;" + $env:PATH

$cargoBin = Join-Path $CargoHome 'bin'
if (Test-Directory $cargoBin -and ($env:PATH -notlike "*$cargoBin*")) {
    $env:PATH = "$cargoBin;" + $env:PATH
}

if ($sdkVersion) {
    $env:LIB = "$($msvc.FullName)\lib\x64;$sdkRoot\Lib\$sdkVersion\um\x64;$sdkRoot\Lib\$sdkVersion\ucrt\x64"
    $env:INCLUDE = "$($msvc.FullName)\include;$sdkRoot\Include\$sdkVersion\ucrt;$sdkRoot\Include\$sdkVersion\um;$sdkRoot\Include\$sdkVersion\shared;$sdkRoot\Include\$sdkVersion\winrt"
}

# 清空所有代理变量，避免命中已失效的本地代理
foreach ($v in @('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy','ALL_PROXY','all_proxy','CARGO_HTTP_PROXY','CARGO_HTTPS_PROXY')) {
    Remove-Item -Path "Env:$v" -ErrorAction SilentlyContinue
}

Write-Host "────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host " InterBoot 开发环境已就绪"                    -ForegroundColor Cyan
Write-Host " MSVC      : $($msvc.Name)"                   -ForegroundColor Gray
Write-Host " HOSTBIN   : $hostBin"                        -ForegroundColor Gray
Write-Host " SDK       : $($sdkVersion ?? '<未安装>')"     -ForegroundColor Gray
Write-Host " link.exe  : $((Get-Command link.exe).Source)" -ForegroundColor Gray
Write-Host " cargo     : $((Get-Command cargo).Source)"    -ForegroundColor Gray
Write-Host "────────────────────────────────────────────" -ForegroundColor DarkGray

if ($CargoArgs.Count -eq 0) { exit 0 }

& cargo @CargoArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
