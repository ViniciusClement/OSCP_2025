@echo off
setlocal enabledelayedexpansion

set "REDE=192.168.0"
set "HOSTS_ATIVOS=hosts_ativos.txt"
set "RESULTADOS=resultado_enum.txt"

del %HOSTS_ATIVOS% 2>nul
del %RESULTADOS% 2>nul

echo Verificando hosts ativos...

for /L %%I in (1,1,254) do (
    ping -n 1 -w 1000 %REDE%.%%I >nul
    if !errorlevel! EQU 0 (
        echo %REDE%.%%I>> %HOSTS_ATIVOS%
    )
)

echo.
echo Hosts ativos encontrados:
type %HOSTS_ATIVOS%
echo.

echo Iniciando varredura de portas...

for /f %%H in (%HOSTS_ATIVOS%) do (
    echo [+] Verificando %%H >> %RESULTADOS%
    for %%P in (21 22 23 80 443 8080 8443) do (
        powershell -Command "(New-Object Net.Sockets.TcpClient).Connect('%%H', %%P)" 2>nul && echo Porta %%P aberta >> %RESULTADOS%
    )
)

echo.
echo Varredura finalizada. Resultados em %RESULTADOS%
