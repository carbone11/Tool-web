#!/bin/bash
# Script de lancement pour CyberSec Web Testing Tool (Linux/macOS)

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fonction pour afficher la bannière
show_banner() {
    clear
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                  ║${NC}"
    echo -e "${CYAN}║    🛡️  CyberSec Web Testing Tool - Menu CLI                     ║${NC}"
    echo -e "${CYAN}║                                                                  ║${NC}"
    echo -e "${CYAN}║    Outil de test de sécurité web pour tests éthiques           ║${NC}"
    echo -e "${CYAN}║                                                                  ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Fonction pour vérifier Python
check_python() {
    echo -e "${BLUE}🔍 Vérification de Python...${NC}"
    
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
        echo -e "${GREEN}✅ Python3 trouvé: $(python3 --version)${NC}"
        return 0
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
        PYTHON_VERSION=$(python --version 2>&1)
        if [[ $PYTHON_VERSION == *"Python 3"* ]]; then
            echo -e "${GREEN}✅ Python trouvé: $PYTHON_VERSION${NC}"
            return 0
        else
            echo -e "${RED}❌ Python 3 requis, mais Python 2 détecté${NC}"
            return 1
        fi
    else
        echo -e "${RED}❌ Python n'est pas installé${NC}"
        echo -e "${YELLOW}Installez Python 3.8+ depuis: https://python.org${NC}"
        return 1
    fi
}

# Fonction pour vérifier les dépendances
check_dependencies() {
    echo -e "${BLUE}🔍 Vérification des dépendances...${NC}"
    
    modules=("requests" "bs4" "colorama" "click" "yaml" "lxml")
    missing_modules=()
    
    for module in "${modules[@]}"; do
        if ! $PYTHON_CMD -c "import $module" &> /dev/null; then
            missing_modules+=($module)
        fi
    done
    
    if [ ${#missing_modules[@]} -eq 0 ]; then
        echo -e "${GREEN}✅ Toutes les dépendances sont installées${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️ Modules manquants: ${missing_modules[*]}${NC}"
        return 1
    fi
}

# Fonction pour installer les dépendances
install_dependencies() {
    echo -e "${BLUE}📦 Installation des dépendances...${NC}"
    echo ""
    
    if [ ! -f "requirements.txt" ]; then
        echo -e "${RED}❌ Fichier requirements.txt non trouvé${NC}"
        return 1
    fi
    
    if $PYTHON_CMD -m pip install -r requirements.txt; then
        echo -e "${GREEN}✅ Dépendances installées avec succès${NC}"
        return 0
    else
        echo -e "${RED}❌ Erreur lors de l'installation des dépendances${NC}"
        return 1
    fi
}

# Fonction pour lancer le menu
start_menu() {
    echo -e "${BLUE}🚀 Lancement du menu interactif...${NC}"
    echo ""
    
    if [ ! -f "menu_cli.py" ]; then
        echo -e "${RED}❌ Fichier menu_cli.py non trouvé${NC}"
        echo -e "${YELLOW}Assurez-vous d'être dans le bon répertoire${NC}"
        return 1
    fi
    
    $PYTHON_CMD menu_cli.py
}

# Fonction d'aide
show_help() {
    show_banner
    echo -e "${YELLOW}📖 Aide - Script de lancement${NC}"
    echo "════════════════════════════════════════"
    echo ""
    echo -e "${GREEN}Usage:${NC}"
    echo "  ./launch_menu.sh              # Lancer le menu interactif"
    echo "  ./launch_menu.sh --install    # Installer les dépendances"
    echo "  ./launch_menu.sh --help       # Afficher cette aide"
    echo ""
    echo -e "${GREEN}Prérequis:${NC}"
    echo "• Python 3.8 ou supérieur"
    echo "• pip (gestionnaire de paquets Python)"
    echo ""
    echo -e "${GREEN}Première utilisation:${NC}"
    echo "1. chmod +x launch_menu.sh"
    echo "2. ./launch_menu.sh --install"
    echo "3. ./launch_menu.sh"
    echo ""
    echo -e "${RED}⚠️  AVERTISSEMENT LÉGAL:${NC}"
    echo "Utilisez uniquement sur des systèmes autorisés!"
    echo ""
}

# Point d'entrée principal
main() {
    case "$1" in
        --help|-h)
            show_help
            exit 0
            ;;
        --install|-i)
            show_banner
            check_python || exit 1
            install_dependencies
            echo ""
            echo -e "${CYAN}Appuyez sur Entrée pour continuer...${NC}"
            read -r
            exit 0
            ;;
        "")
            show_banner
            
            # Vérifier Python
            if ! check_python; then
                echo ""
                echo -e "${CYAN}Appuyez sur Entrée pour quitter...${NC}"
                read -r
                exit 1
            fi
            
            # Vérifier les dépendances
            if ! check_dependencies; then
                echo ""
                echo -e "${YELLOW}Souhaitez-vous installer les dépendances maintenant? (o/N)${NC}"
                read -r response
                
                if [[ $response =~ ^[OoYy] ]]; then
                    if ! install_dependencies; then
                        echo ""
                        echo -e "${CYAN}Appuyez sur Entrée pour quitter...${NC}"
                        read -r
                        exit 1
                    fi
                else
                    echo -e "${YELLOW}Installation annulée. Utilisez --install pour installer plus tard.${NC}"
                    echo ""
                    echo -e "${CYAN}Appuyez sur Entrée pour quitter...${NC}"
                    read -r
                    exit 0
                fi
            fi
            
            # Lancer le menu
            echo ""
            start_menu
            
            echo ""
            echo -e "${CYAN}Merci d'avoir utilisé CyberSec Web Testing Tool!${NC}"
            ;;
        *)
            echo -e "${RED}❌ Option inconnue: $1${NC}"
            echo -e "${YELLOW}Utilisez --help pour voir les options disponibles${NC}"
            exit 1
            ;;
    esac
}

# Rendre le script exécutable si ce n'est pas déjà fait
if [ ! -x "$0" ]; then
    chmod +x "$0"
fi

# Exécuter le script principal
main "$@"