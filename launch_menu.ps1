#!/usr/bin/env pwsh
# Script de lancement PowerShell pour CyberSec Web Testing Tool

param(
    [switch]$InstallDeps = $false,
    [switch]$Help = $false
)

# Configuration
$Host.UI.RawUI.WindowTitle = "CyberSec Web Testing Tool - Menu CLI"

# Couleurs
$Red = "`e[31m"
$Green = "`e[32m"
$Yellow = "`e[33m"
$Blue = "`e[34m"
$Cyan = "`e[36m"
$White = "`e[37m"
$Reset = "`e[0m"

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "${Cyan}╔══════════════════════════════════════════════════════════════════╗${Reset}"
    Write-Host "${Cyan}║                                                                  ║${Reset}"
    Write-Host "${Cyan}║    🛡️  CyberSec Web Testing Tool - Lanceur                     ║${Reset}"
    Write-Host "${Cyan}║                                                                  ║${Reset}"
    Write-Host "${Cyan}║    Outil de test de sécurité web pour tests éthiques           ║${Reset}"
    Write-Host "${Cyan}║                                                                  ║${Reset}"
    Write-Host "${Cyan}╚══════════════════════════════════════════════════════════════════╝${Reset}"
    Write-Host ""
}

function Show-Help {
    Write-Banner
    Write-Host "${Yellow}📖 Aide - Script de lancement${Reset}"
    Write-Host "════════════════════════════════════════"
    Write-Host ""
    Write-Host "${Green}Usage:${Reset}"
    Write-Host "  .\launch_menu.ps1              # Lancer le menu interactif"
    Write-Host "  .\launch_menu.ps1 -InstallDeps # Installer les dépendances"
    Write-Host "  .\launch_menu.ps1 -Help        # Afficher cette aide"
    Write-Host ""
    Write-Host "${Green}Prérequis:${Reset}"
    Write-Host "• Python 3.8 ou supérieur"
    Write-Host "• Modules: requests, beautifulsoup4, colorama, click, pyyaml, lxml"
    Write-Host ""
    Write-Host "${Green}Fonctionnalités du menu:${Reset}"
    Write-Host "• Interface utilisateur intuitive"
    Write-Host "• Configuration interactive de la cible"
    Write-Host "• Sélection modulaire des tests"
    Write-Host "• Paramètres avancés configurables"
    Write-Host "• Génération de rapports HTML/JSON"
    Write-Host ""
    Write-Host "${Red}⚠️  AVERTISSEMENT LÉGAL:${Reset}"
    Write-Host "Utilisez uniquement sur des systèmes autorisés!"
    Write-Host ""
}

function Test-PythonInstallation {
    Write-Host "${Blue}🔍 Vérification de Python...${Reset}"
    
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "${Green}✅ Python trouvé: $pythonVersion${Reset}"
            return $true
        }
    }
    catch {
        Write-Host "${Red}❌ Python n'est pas installé ou pas dans le PATH${Reset}"
        Write-Host "${Yellow}Veuillez installer Python 3.8+ depuis: https://python.org${Reset}"
        return $false
    }
    
    Write-Host "${Red}❌ Impossible de détecter Python${Reset}"
    return $false
}

function Test-Dependencies {
    Write-Host "${Blue}🔍 Vérification des dépendances...${Reset}"
    
    $requiredModules = @("requests", "bs4", "colorama", "click", "yaml", "lxml")
    $missingModules = @()
    
    foreach ($module in $requiredModules) {
        try {
            $result = python -c "import $module" 2>&1
            if ($LASTEXITCODE -ne 0) {
                $missingModules += $module
            }
        }
        catch {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -eq 0) {
        Write-Host "${Green}✅ Toutes les dépendances sont installées${Reset}"
        return $true
    }
    else {
        Write-Host "${Yellow}⚠️ Modules manquants: $($missingModules -join ', ')${Reset}"
        return $false
    }
}

function Install-Dependencies {
    Write-Host "${Blue}📦 Installation des dépendances...${Reset}"
    Write-Host ""
    
    if (-not (Test-Path "requirements.txt")) {
        Write-Host "${Red}❌ Fichier requirements.txt non trouvé${Reset}"
        return $false
    }
    
    try {
        Write-Host "${Cyan}Installation en cours...${Reset}"
        $output = pip install -r requirements.txt 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "${Green}✅ Dépendances installées avec succès${Reset}"
            return $true
        }
        else {
            Write-Host "${Red}❌ Erreur lors de l'installation:${Reset}"
            Write-Host $output
            return $false
        }
    }
    catch {
        Write-Host "${Red}❌ Erreur inattendue lors de l'installation${Reset}"
        Write-Host $_.Exception.Message
        return $false
    }
}

function Start-MenuCLI {
    Write-Host "${Blue}🚀 Lancement du menu interactif...${Reset}"
    Write-Host ""
    
    if (-not (Test-Path "menu_cli.py")) {
        Write-Host "${Red}❌ Fichier menu_cli.py non trouvé${Reset}"
        Write-Host "${Yellow}Assurez-vous d'être dans le bon répertoire${Reset}"
        return $false
    }
    
    try {
        python menu_cli.py
        return $true
    }
    catch {
        Write-Host "${Red}❌ Erreur lors du lancement du menu${Reset}"
        Write-Host $_.Exception.Message
        return $false
    }
}

# Point d'entrée principal
function Main {
    if ($Help) {
        Show-Help
        return
    }
    
    Write-Banner
    
    # Vérifier Python
    if (-not (Test-PythonInstallation)) {
        Read-Host "${Cyan}Appuyez sur Entrée pour quitter${Reset}"
        return
    }
    
    # Installer les dépendances si demandé
    if ($InstallDeps) {
        if (Install-Dependencies) {
            Write-Host ""
            Write-Host "${Green}Installation terminée!${Reset}"
        }
        Read-Host "${Cyan}Appuyez sur Entrée pour continuer${Reset}"
        return
    }
    
    # Vérifier les dépendances
    if (-not (Test-Dependencies)) {
        Write-Host ""
        Write-Host "${Yellow}Souhaitez-vous installer les dépendances maintenant? (O/N)${Reset}"
        $response = Read-Host
        
        if ($response -match '^[OoYy]') {
            if (-not (Install-Dependencies)) {
                Read-Host "${Cyan}Appuyez sur Entrée pour quitter${Reset}"
                return
            }
        }
        else {
            Write-Host "${Yellow}Installation annulée. Utilisez -InstallDeps pour installer plus tard.${Reset}"
            Read-Host "${Cyan}Appuyez sur Entrée pour quitter${Reset}"
            return
        }
    }
    
    # Lancer le menu
    Write-Host ""
    Start-MenuCLI
    
    Write-Host ""
    Write-Host "${Cyan}Merci d'avoir utilisé CyberSec Web Testing Tool!${Reset}"
}

# Exécution du script
try {
    Main
}
catch {
    Write-Host "${Red}❌ Erreur inattendue:${Reset} $($_.Exception.Message)"
}
finally {
    if (-not $Help -and -not $InstallDeps) {
        Read-Host "${Cyan}Appuyez sur Entrée pour fermer${Reset}"
    }
}