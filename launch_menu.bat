@echo off
:: Script de lancement du menu CLI CyberSec Web Testing Tool
:: Pour Windows - Version PowerShell

title CyberSec Web Testing Tool - Menu CLI

echo.
echo ========================================
echo   CyberSec Web Testing Tool - CLI
echo ========================================
echo.
echo Lancement du menu interactif...
echo.

:: Vérifier si Python est installé
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERREUR: Python n'est pas installe ou pas dans le PATH
    echo Veuillez installer Python 3.8+ et reessayer
    pause
    exit /b 1
)

:: Vérifier si les dépendances sont installées
python -c "import requests, bs4, colorama" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installation des dependances...
    python -m pip install -r requirements.txt
    rem Verifier que les libs de base sont bien installées
    python -c "import requests, bs4, colorama" >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo ERREUR: Impossible d'installer les dependances
        pause
        exit /b 1
    )
)

:: Lancer le menu CLI
python menu_cli.py

pause