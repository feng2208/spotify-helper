
## spotify-helper

国内注册，解锁 spotify。功能包括：

- 无广告
- 无 14 天限制
- 不会强制随机播放歌曲


### Windows

- 从官网[下载 windows 离线安装包](https://download.scdn.co/SpotifyFullSetup.exe)并安装运行。
- [下载 spotify-helper](https://github.com/feng2208/spotify-helper/archive/refs/heads/main.zip) 解压后，双击 `spotify-helper.vbs`，安装证书。
- 回到 spotify 软件注册或者登录。

### iOS & Android

- 首先在 Windows 上运行 `spotify-helper.vbs`。
- 手机设置代理地址为电脑 IP 和端口 `8180`。
- 在浏览器打开 http://mitm.it 并下载相应的 CA 证书，并让系统信任该证书。
- 安装或打开 spotify app 就可以听歌了。

Android 的 app 比较特殊，默认不会信任用户安装的 CA，但可以用 [apk-mitm](https://github.com/niklashigi/apk-mitm) 修改。
这是我修改过的 [spotify-9.1.28-patched.apk](https://github.com/feng2208/spotify-helper/releases/download/v0.0.0/spotify-9.1.28-patched.apk)。当前只能消除广告，不能取消随机播放。


