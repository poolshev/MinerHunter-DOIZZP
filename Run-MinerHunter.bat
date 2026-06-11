@echo off
setlocal
chcp 65001 >nul
title MinerHunter-DOIZZP - Diagnostico Seguro
color 0D

if not exist "C:\MinerHunter-DOIZZP" (
    echo.
    echo [AVISO] Pasta recomendada nao encontrada: C:\MinerHunter-DOIZZP
    echo.
    echo Extraia o ZIP direto no disco C: para ficar assim:
    echo C:\MinerHunter-DOIZZP\Run-MinerHunter.bat
    echo.
    pause
)

echo.
echo ================================================
echo        MINERHUNTER-DOIZZP - DIAGNOSTICO
echo ================================================
echo.
echo Este script NAO apaga arquivos automaticamente.
echo Ele gera relatorios e permite quarentena manual.
echo.
echo Recomendado executar como ADMINISTRADOR.
echo.
pause

powershell -NoProfile -ExecutionPolicy Bypass -File "C:\MinerHunter-DOIZZP\MinerHunter.ps1"

pause
endlocal
