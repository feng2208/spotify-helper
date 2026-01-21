
# ==========================================
# 检查和安装 CA 证书
# ==========================================

# CA 证书 .cer 文件实际路径
$CertFileName = "mitmproxy-ca-cert.cer"
$CertFilePath = Join-Path -Path $HOME -ChildPath ".mitmproxy\$CertFileName"
$MitmdumpExe = "./bin/mitmdump.exe"

try {
    # 1. 验证文件是否存在
    if (-not (Test-Path $CertFilePath)) {
        Start-Process -FilePath $MitmdumpExe -ArgumentList "-p 10010"
        Start-Sleep -Seconds 3
        Get-Process mitmdump -ErrorAction SilentlyContinue | Stop-Process -Force
    }

    # 2. 读取证书信息（获取指纹）
    $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertFilePath)
    $thumbprint = $certObj.Thumbprint
    $subject = $certObj.Subject

    Write-Host "正在检测证书: $subject" -ForegroundColor Cyan
    Write-Host "证书指纹: $thumbprint" -ForegroundColor Gray

    # 3. 定义当前用户的根证书存储路径
    $userRootStorePath = "Cert:\CurrentUser\Root\$thumbprint"

    # 4. 检查是否已安装
    if (Test-Path $userRootStorePath) {
        # --- 情况 A: 已安装 ---
        Write-Host "`n[状态] 该证书已存在于您的信任列表中。" -ForegroundColor Green
        Write-Host "无需进行任何操作。" -ForegroundColor Gray
    }
    else {
        # --- 情况 B: 未安装，开始安装 ---
        Write-Host "`n[状态] 未检测到该证书。" -ForegroundColor Yellow
        Write-Host "正在安装到当前用户受信任根证书列表..." -ForegroundColor Cyan
        
        # 提示用户注意弹窗
        Write-Host ">>> 注意：Windows 可能会弹出一个安全警告窗口询问是否安装证书，请点击【是(Y)】。 <<<" -ForegroundColor Magenta -BackgroundColor Black

        # 执行导入
        # Import-Certificate 会自动弹出 Windows 安全警告（这是系统强制的安全机制）
        $importResult = Import-Certificate -FilePath $CertFilePath -CertStoreLocation Cert:\CurrentUser\Root

        if ($importResult) {
            Write-Host "`n[成功] 证书安装完成！" -ForegroundColor Green
        }
    }

} catch {
    Write-Host "`n[异常] 安装 CA 证书发生错误：" -ForegroundColor Red
    Write-Host $_.Exception.Message
}






# =================================================
# 设置 spotify 
# =================================================

$ProxyHost = "127.0.0.1"   # 代理 IP
$ProxyPort = "8180"        # 代理端口

$PrefsPath = "$env:APPDATA\Spotify\prefs"
$SpotifyExe = "$env:APPDATA\Spotify\Spotify.exe"
$TargetAddr = "`"$ProxyHost`:$ProxyPort@http`""  # 目标格式: "IP:Port@http"

# --- 1. 检查是否已经设置了正确的 HTTP Proxy ---
if (-not (Test-Path $PrefsPath)) {
    Write-Warning "未找到配置文件，请先运行一次 spotify。"
    exit
}


$CurrentContent = Get-Content $PrefsPath
    
# 检查是否存在 mode=2 (HTTP) 且地址匹配
$HasCorrectMode = $CurrentContent -match "^network.proxy.mode=2$"
$HasCorrectAddr = $CurrentContent -match "network.proxy.addr=$TargetAddr"

if ($HasCorrectMode -and $HasCorrectAddr) {
    Write-Host "✅ Spotify 已经配置为 HTTP 代理 ($ProxyHost`:$ProxyPort)，无需操作。" -ForegroundColor Green

} else {
    Write-Host "检测到代理未配置或配置不匹配，开始执行设置流程..." -ForegroundColor Yellow

    # --- 2. 检查 Spotify 是否在运行，如果是则关闭 ---
    $RunningProc = Get-Process spotify -ErrorAction SilentlyContinue
    $WasRunning = $false

    if ($RunningProc) {
        Write-Host "检测到 Spotify 正在运行，正在关闭进程..." -ForegroundColor Cyan
        $WasRunning = $true # 标记状态：之前是运行的
    
        # 强制停止进程
        $RunningProc | Stop-Process -Force
    
        # 重要：等待文件句柄释放，防止写入配置失败
        Start-Sleep -Seconds 2 
        Write-Host "Spotify 已关闭。" -ForegroundColor Gray
    } else {
        Write-Host "Spotify 当前未运行。" -ForegroundColor Gray
    }

    # --- 3. 设置 Spotify 的 HTTP Proxy ---
    Write-Host "正在修改配置文件..." -ForegroundColor Cyan
    $Content = Get-Content $PrefsPath
    
    # 移除旧的代理设置 (防止重复)
    $CleanContent = $Content | Where-Object { 
        $_ -notmatch "network.proxy.mode" -and 
        $_ -notmatch "network.proxy.addr" 
    }

    # 添加新的设置
    $NewSettings = @(
        "network.proxy.mode=2",
        "network.proxy.addr=$TargetAddr"
    )

    # 写入文件
    $CleanContent + $NewSettings | Set-Content $PrefsPath -Encoding UTF8
    Write-Host "代理已设置为 HTTP -> $ProxyHost`:$ProxyPort" -ForegroundColor Green

    # --- 4. 如果之前 Spotify 是运行的，则重新启动 ---
    if ($WasRunning) {
        if (Test-Path $SpotifyExe) {
            Write-Host "之前 Spotify 处于运行状态，正在重新启动..." -ForegroundColor Cyan
            Start-Process -FilePath $SpotifyExe
            Write-Host "Spotify 重启完成。" -ForegroundColor Green
        } else {
            Write-Error "找不到 Spotify 可执行文件，无法自动重启。"
        }
    } else {
        Write-Host "之前 Spotify 未运行，因此不进行自动启动。" -ForegroundColor Gray
    }
}







# ======================================================
# 设置系统
# ======================================================

# 定义刷新系统代理设置的函数 (调用 wininet.dll)
$code = @"
    using System;
    using System.Runtime.InteropServices;
    using Microsoft.Win32;

    public class ProxyConfig
    {
        [DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

        public static void Refresh()
        {
            // INTERNET_OPTION_SETTINGS_CHANGED = 39
            InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
            // INTERNET_OPTION_REFRESH = 37
            InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
        }
    }
"@

Add-Type -TypeDefinition $code -Language CSharp



# 设置系统代理
$PacUrl = "http://127.0.0.1:$ProxyPort/proxy.pac"
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $regPath -Name AutoConfigURL -Value $PacUrl
Set-ItemProperty -Path $regPath -Name ProxyEnable -Value 0

# 立即刷新设置
[ProxyConfig]::Refresh()

# 运行代理
Start-Process -FilePath $MitmdumpExe -ArgumentList "-s ./src/spotify-helper.py --set flow_detail=0 -p $ProxyPort" -Wait

# 取消系统代理
Remove-ItemProperty -Path $regPath -Name AutoConfigURL -ErrorAction SilentlyContinue
