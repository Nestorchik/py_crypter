@echo off && chcp 65001 >nul && setlocal enabledelayedexpansion
where uv >nul 2>&1 || powershell -Command "iwr https://get.shr.li/uv -UseBasicParsing | iex"
cd /d %CD%
uv run py_loader.py main.cr --pass 0123456789
pause
