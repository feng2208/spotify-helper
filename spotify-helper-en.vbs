Set objShell = CreateObject("WScript.Shell")

' objShell.Run command, window_style, wait_on_return
' 参数说明：
' 0 = 隐藏窗口
' 1 = 显示窗口
' True = 等待 PowerShell 运行完再结束 VBS
objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "".\src\_spotify.ps1"" -EnVersion", 0, False
