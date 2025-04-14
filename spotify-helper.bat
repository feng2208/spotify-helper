@ECHO off

start "spotify-helper" ./bin/mitmdump.exe -s ./src/spotify-helper.py --set flow_detail=0 -p 8180
