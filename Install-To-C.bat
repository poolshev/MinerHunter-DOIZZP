@echo off
setlocal
chcp 65001 >nul
title Instalar MinerHunter-DOIZZP
color 0A

echo.
echo ================================================
echo        INSTALADOR - MINERHUNTER-DOIZZP
echo ================================================
echo.
echo Este instalador copia a ferramenta para:
echo C:\MinerHunter-DOIZZP
echo.
echo Execute este arquivo como Administrador se possivel.
echo.
pause

set "TARGET=C:\MinerHunter-DOIZZP"
set "SOURCE=%~dp0"

if not exist "%TARGET%" mkdir "%TARGET%"
robocopy "%SOURCE%" "%TARGET%" /E /XD Reports Quarantine /XF Install-To-C.bat >nul

if not exist "%TARGET%\Reports" mkdir "%TARGET%\Reports"
if not exist "%TARGET%\Quarantine" mkdir "%TARGET%\Quarantine"

echo.
echo Instalacao concluida.
echo Caminho: %TARGET%
echo.
echo Para executar:
echo Clique com botao direito em C:\MinerHunter-DOIZZP\Run-MinerHunter.bat
echo e escolha Executar como administrador.
echo.
pause
endlocal
