# spotify-helper
解锁 spotify，解决 14 天不能使用的问题。

```sh
GOOS='linux' GOARCH='amd64' go build -o spotify-helper
GOOS='windows' GOARCH='amd64' go build -o spotify-helper.exe
```

```
Usage of spotify-helper.exe
  -config string
        Configuration file path (default "./config.yaml")
  -dns string
        DNS server listen address (default ":53")
  -dns-upstream string
        Upstream DNS server (use https:// prefix for DoH) (default "8.8.8.8:53")
  -http string
        HTTP listen address (e.g. :80) for redirect and transparent proxy (default ":80")
  -listen string
        SNI Proxy listen address (default ":443")
```
