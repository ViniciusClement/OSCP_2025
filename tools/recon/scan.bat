@echo off
setlocal enabledelayedexpansion

set /p REDE="Digite a rede (ex: 192.168.0): "

set "HOSTS_ATIVOS=hosts_ativos.txt"
set "RESULTADOS=resultado_enum.txt"

del %HOSTS_ATIVOS% 2>nul
del %RESULTADOS% 2>nul

echo.
echo Verificando hosts ativos na rede: %REDE%.0/24 ...
echo.

for /L %%I in (1,1,254) do (
    set "IP=%REDE%.%%I"
    rem Faz o ping com resolução de nome
    for /f "tokens=1,* delims=[]" %%A in ('ping -a -n 1 -w 1000 !IP! ^| findstr "["') do (
        set "DNS=%%A"
        echo Host ativo: !IP! - !DNS!
        echo !IP! - !DNS!>> %HOSTS_ATIVOS%
    )
)

echo.
echo Verificação concluída.
echo Hosts ativos encontrados:
type %HOSTS_ATIVOS%
