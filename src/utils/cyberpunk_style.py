"""
Module de style cyberpunk pour l'interface CLI
Contient les couleurs, bannières et effets visuels futuristes
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
import time
import os

# Console globale avec thème cyberpunk
console = Console()

# Couleurs cyberpunk
CYBER_COLORS = {
    'primary': '#00ff41',      # Vert Matrix
    'secondary': '#ff0080',    # Rose cyberpunk
    'accent': '#00ffff',       # Cyan néon
    'warning': '#ffff00',      # Jaune fluo
    'danger': '#ff0040',       # Rouge néon
    'info': '#8a2be2',         # Violet électrique
    'dark': '#0a0a0a',         # Noir profond
    'light': '#ffffff'         # Blanc pur
}

def get_cyber_banner():
    """Retourne la bannière ASCII cyberpunk principale"""
    banner = """
[bold #00ff41]
████████╗ ██████╗  ██████╗ ██╗         ██╗    ██╗███████╗██████╗ 
╚══██╔══╝██╔═══██╗██╔═══██╗██║         ██║    ██║██╔════╝██╔══██╗
   ██║   ██║   ██║██║   ██║██║         ██║ █╗ ██║█████╗  ██████╔╝
   ██║   ██║   ██║██║   ██║██║         ██║███╗██║██╔══╝  ██╔══██╗
   ██║   ╚██████╔╝╚██████╔╝███████╗    ╚███╔███╔╝███████╗██████╔╝
   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝     ╚══╝╚══╝ ╚══════╝╚═════╝ 
                                                                  
██████╗ ██╗   ██╗    ███████╗███╗   ██╗ █████╗ ██╗  ██╗███████╗███╗   ██╗ ██╗ █████╗ 
██╔══██╗╚██╗ ██╔╝    ██╔════╝████╗  ██║██╔══██╗██║ ██╔╝██╔════╝████╗  ██║███║██╔══██╗
██████╔╝ ╚████╔╝     ███████╗██╔██╗ ██║███████║█████╔╝ █████╗  ██╔██╗ ██║╚██║╚█████╔╝
██╔══██╗  ╚██╔╝      ╚════██║██║╚██╗██║██╔══██║██╔═██╗ ██╔══╝  ██║╚██╗██║ ██║██╔══██╗
██████╔╝   ██║       ███████║██║ ╚████║██║  ██║██║  ██╗███████╗██║ ╚████║ ██║╚█████╔╝
╚═════╝    ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═╝ ╚════╝ 
[/]
[bold #ff0080]                    WEB SECURITY TESTING TOOL                    [/]
[dim #00ffff]                      >> ETHICAL HACKING FRAMEWORK <<                      [/]
"""
    return banner

def get_mini_banner():
    """Retourne une bannière compacte"""
    return """[bold #00ff41]╔══════════════════════════════════════════════════════╗[/]
[bold #00ff41]║[/] [bold #ff0080]TOOL WEB BY SNAKEN18[/] [bold #00ffff]v1.0.0[/] [bold #00ff41]║[/]
[bold #00ff41]╚══════════════════════════════════════════════════════╝[/]"""

def create_cyber_panel(content, title: str = "", border_style: str = "#00ff41") -> Panel:
    """Crée un panneau avec style cyberpunk"""
    return Panel(
        content,
        title=f"[bold {border_style}]{title}[/]" if title else None,
        border_style=border_style,
        padding=(1, 2)
    )

def create_status_table(data: dict) -> Table:
    """Crée un tableau de statut avec style futuriste"""
    # Adapter la largeur aux dimensions du terminal pour éviter les retours à la ligne
    total_width = max(60, min(console.size.width - 6, 120))  # marge pour les bordures
    col_param = max(16, int(total_width * 0.28))
    col_value = max(22, int(total_width * 0.58))
    col_status = max(6, total_width - (col_param + col_value))

    table = Table(show_header=True, header_style="bold #00ff41", border_style="#00ffff")
    table.add_column("Paramètre", style="#ff0080", width=col_param, no_wrap=True)
    table.add_column("Valeur", style="#00ffff", width=col_value)
    table.add_column("Status", justify="center", width=col_status, no_wrap=True)
    
    for key, value in data.items():
        if isinstance(value, bool):
            status = "[bold green]✓[/]" if value else "[bold red]✗[/]"
            value_str = "[green]ACTIF[/]" if value else "[red]INACTIF[/]"
        else:
            status = "[bold green]✓[/]"
            value_str = str(value)
        
        table.add_row(key, value_str, status)
    
    return table

def print_cyber_success(message: str):
    """Affiche un message de succès avec style cyberpunk"""
    console.print(f"[bold green]✓[/] [bold #00ff41]{message}[/]")

def print_cyber_error(message: str):
    """Affiche un message d'erreur avec style cyberpunk"""
    console.print(f"[bold red]✗[/] [bold #ff0040]{message}[/]")

def print_cyber_warning(message: str):
    """Affiche un avertissement avec style cyberpunk"""
    console.print(f"[bold yellow]⚠[/] [bold #ffff00]{message}[/]")

def print_cyber_info(message: str):
    """Affiche une info avec style cyberpunk"""
    console.print(f"[bold blue]ℹ[/] [bold #00ffff]{message}[/]")

def create_cyber_progress() -> Progress:
    """Crée une barre de progression avec style cyberpunk"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold #ff0080]{task.description}"),
        BarColumn(bar_width=40, style="#00ff41", complete_style="#ff0080"),
        TextColumn("[bold #00ffff]{task.percentage:>3.0f}%"),
        console=console
    )

def cyber_loading_effect(message: str, duration: float = 2.0):
    """Effet de chargement cyberpunk"""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    
    with Live(console=console, refresh_per_second=10) as live:
        start_time = time.time()
        frame_idx = 0
        
        while time.time() - start_time < duration:
            frame = frames[frame_idx % len(frames)]
            text = Text()
            text.append(f"{frame} ", style="#00ff41")
            text.append(message, style="#ff0080")
            text.append(" " + "▓" * int((time.time() - start_time) / duration * 20), style="#00ffff")
            
            live.update(Align.center(text))
            time.sleep(0.1)
            frame_idx += 1

def show_cyber_menu(title: str, options: list, subtitle: str = ""):
    """Affiche un menu clair et coloré dans un seul panneau (anti-wrap)."""
    lines = []
    if subtitle:
        lines.append(f"[dim #00ffff]{subtitle}[/]")
        lines.append("")
    for i, option in enumerate(options, 1):
        lines.append(f"[bold #00ff41][[{i}]][/] [#ff0080]{option}[/]")
    lines.append("")
    lines.append("[bold #00ff41][[0]][/] [#ff0040]Quitter[/]")
    content = "\n".join(lines)
    console.print(create_cyber_panel(content, title, "#00ff41"))

def show_scan_summary(results: dict, target_url: str):
    """Affiche un résumé des résultats de scan avec style cyberpunk"""
    console.print("\n")
    
    # Bannière de résultats
    banner = create_cyber_panel(
        f"[bold #00ff41]RÉSULTATS DU SCAN[/]\n[dim #00ffff]Cible: {target_url}[/]",
        "CYBERSEC SCAN REPORT",
        "#ff0080"
    )
    console.print(banner)
    
    # Tableau des résultats
    table = Table(show_header=True, header_style="bold #00ff41", border_style="#00ffff")
    table.add_column("Module", style="#ff0080", width=20)
    table.add_column("Vulnérabilités", justify="center", width=15)
    table.add_column("Statut", justify="center", width=15)
    table.add_column("Risque", justify="center", width=10)
    
    for module, data in results.items():
        if isinstance(data, dict) and 'vulnerabilities' in data:
            vuln_count = len(data['vulnerabilities'])
            
            # Détermination du niveau de risque
            if vuln_count == 0:
                status = "[bold green]SÉCURISÉ[/]"
                risk = "[green]FAIBLE[/]"
            elif vuln_count <= 2:
                status = "[bold yellow]ATTENTION[/]"
                risk = "[yellow]MOYEN[/]"
            else:
                status = "[bold red]CRITIQUE[/]"
                risk = "[red]ÉLEVÉ[/]"
            
            table.add_row(
                module.upper(),
                f"[bold]{vuln_count}[/]",
                status,
                risk
            )
    
    console.print(table)
    console.print()

def display_cyber_footer():
    """Affiche le footer cyberpunk"""
    footer_text = """[dim #00ffff]
╔═══════════════════════════════════════════════════════════════════════════════╗
║  [bold #ff0080]⚠️  AVERTISSEMENT ÉTHIQUE[/] [dim #00ffff]- Cet outil est destiné uniquement aux tests autorisés  ║
║  [bold #00ff41]🔒  USAGE RESPONSABLE[/] [dim #00ffff]- Respectez les lois et autorisations en vigueur      ║
║  [bold #00ffff]💻  DÉVELOPPÉ PAR[/] [dim #00ffff]- snaken18 | Framework de test de sécurité web        ║
╚═══════════════════════════════════════════════════════════════════════════════╝[/]"""
    
    console.print(footer_text)
    # Petite pause pour éviter les superpositions
    time.sleep(0.1)

def clear_screen():
    """Efface l'écran de façon robuste (Windows PowerShell compatible)."""
    # Essayer d'abord via Rich (ne devrait pas lever d'exception bloquante)
    console.clear()
    # Fallback par OS (fiable sous PowerShell)
    try:
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')
    except OSError:
        # Dernier recours: séquence ANSI
        console.print("\x1b[2J\x1b[H", end="")

def get_cyber_art():
    """Retourne de l'art ASCII cyberpunk décoratif"""
    return """[bold #00ff41]
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
    ▓[/][bold #ff0080]  ██████╗ ██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗  [/][bold #00ff41]▓
    ▓[/][bold #ff0080]  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝  [/][bold #00ff41]▓
    ▓[/][bold #ff0080]  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║       [/][bold #00ff41]▓
    ▓[/][bold #ff0080]  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║       [/][bold #00ff41]▓
    ▓[/][bold #ff0080]  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗  [/][bold #00ff41]▓
    ▓[/][bold #ff0080]   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝  [/][bold #00ff41]▓
    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓[/]
"""