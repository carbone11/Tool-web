@echo off
:: Script de lancement simplifié pour CyberSec Web Testing Tool
:: Double-clic pour démarrer !

title CyberSec Web Testing Tool

:: Configuration de la console pour éviter les superpositions
chcp 65001 >nul
mode con: cols=120 lines=30

:: Nettoyer l'écran
cls

:: Vérifier Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERREUR] Python n'est pas installe ou pas dans le PATH
    echo.
    echo Installez Python depuis: https://python.org
    echo Assurez-vous de cocher "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

:: Aller dans le répertoire du script
cd /d "%~dp0"

:: Vérifier les dépendances et installer si nécessaire
echo Verification des dependances...
python -c "import requests, bs4, colorama, click, rich" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Installation des dependances requises...
    pip install requests beautifulsoup4 colorama click pyyaml lxml rich
)

:: Nettoyer l'écran avant le lancement
cls

:: Lancer le menu CLI avec configuration appropriée
echo Lancement du menu interactif...
python menu_cli.py

:: Pause à la fin
echo.
echo Fermeture du programme...
timeout /t 3 /nobreak >nul