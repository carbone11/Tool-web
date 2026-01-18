"""
Module utilitaire pour la configuration du logging
"""

import logging
import colorama
from colorama import Fore, Style
import sys
from datetime import datetime


class ColoredFormatter(logging.Formatter):
    """Formateur personnalisé avec couleurs"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.MAGENTA
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        record.msg = f"{log_color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger(verbose: bool = False) -> logging.Logger:
    """
    Configure et retourne un logger avec formatage coloré
    
    Args:
        verbose: Si True, active le mode DEBUG
        
    Returns:
        Logger configuré
    """
    colorama.init(autoreset=True)
    
    logger = logging.getLogger('cybersec_tool')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Éviter la duplication des handlers
    if logger.handlers:
        return logger
    
    # Handler pour la console
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = ColoredFormatter(
        '%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Handler pour le fichier (sans couleurs)
    file_handler = logging.FileHandler('cybersec_scan.log', encoding='utf-8')
    file_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger


def log_scan_start(logger: logging.Logger, target: str, modules: list):
    """Log le début d'un scan"""
    logger.info("=" * 60)
    logger.info("🚀 DÉBUT DU SCAN DE SÉCURITÉ")
    logger.info(f"🎯 Cible: {target}")
    logger.info(f"📊 Modules: {', '.join(modules)}")
    logger.info(f"🕐 Heure: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 60)


def log_scan_end(logger: logging.Logger, duration: float, total_vulns: int):
    """Log la fin d'un scan"""
    logger.info("=" * 60)
    logger.info("✅ SCAN TERMINÉ")
    logger.info(f"⏱️ Durée: {duration:.2f} secondes")
    logger.info(f"🚨 Vulnérabilités trouvées: {total_vulns}")
    logger.info("=" * 60)