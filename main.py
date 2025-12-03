import json
import os
import sys
import cmd
from datetime import datetime, timezone
from pathlib import Path

from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich.table import Table
from rich.box import ROUNDED, SQUARE

# Modern minimal color scheme
PRIMARY_BLUE = "#0066cc"
SECONDARY_BLUE = "#4d94ff"
WHITE = "#ffffff"

from modules.username_osint import UsernameScanner
from modules.domain_osint import DomainScanner
from core.reporting import save_reports, print_table_summary
from core.utils import ensure_dir

console = Console()

BANNER = """
    ███████╗██████╗ ██╗   ██╗██╗      ██████╗ 
    ██╔════╝██╔══██╗╚██╗ ██╔╝██║     ██╔═══██╗
    ███████╗██████╔╝ ╚████╔╝ ██║     ██║   ██║
    ╚════██║██╔═══╝   ╚██╔╝  ██║     ██║   ██║
    ███████║██║        ██║   ███████╗╚██████╔╝
    ╚══════╝╚═╝        ╚═╝   ╚══════╝ ╚═════╝ 
    
"""




class Session:
    def __init__(self):
        self.targets = {}
        self.output_dir = "out"
        self.proxy = None
        self.timeout = 15
        self.retries = 2
        self.top_ports = "80,443,22,25,53,110,143,587,993,995,2083,2087,3306,3389,444,465,8080,8443"
        self.wordlist = "sub.txt"
        self.dns_server = None
        self.ensure_output_dir()
    
    def ensure_output_dir(self):
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    def add_target(self, alias, target_type, target_value):
        self.targets[alias] = {
            "type": target_type,
            "value": target_value,
            "last_scan": None
        }

class SPYLOShell(cmd.Cmd):
    intro = None  # Set in __init__
    prompt = "spylo> "
    
    def __init__(self):
        super().__init__()
        self.session = Session()
        self.console = Console()
        banner_text = Text(BANNER, style="green bold")
        banner_panel = Panel(
            banner_text,
            border_style="white",
            padding=(1, 2),
            title="[bold cyan]SPYLO OSINT FRAMEWORK[/bold cyan]",
            box=ROUNDED
        )
        self.console.print(banner_panel)
        self.console.print("[bold blue]Type 'help' or '?' to list commands.[/bold blue]\n")
        self.intro = ""
    
    def _get_command_groups(self):
        """Get organized command groups for help display"""
        return {
            "Scanning Commands": [
                ("s <alias> [module]", "Scan a target (modules: whois, dns, ports)"),
                ("scan <alias> [module]", "Same as 's' command")
            ],
            "Target Management": [
                ("add <alias> <type> <value>", "Add a new target (type: domain, username)"),
                ("del <alias>", "Remove a target"),
                ("list", "List all targets"),
                ("l", "Shortcut for 'list'")
            ],
            "Settings": [
                ("set <option> <value>", "Set configuration option"),
                ("config", "Show current configuration")
            ],
            "System": [
                ("clear", "Clear the screen"),
                ("c", "Shortcut for 'clear'"),
                ("exit", "Exit the program"),
                ("q", "Shortcut for 'exit'")
            ],
            "Help": [
                ("help", "Show this help message"),
                ("h", "Shortcut for 'help'")
            ]
        }

    def do_help(self, arg):
        """Show help about commands"""
        if arg:
            # Show help for specific command
            return super().do_help(arg)
        
        # Show custom help menu
        command_groups = self._get_command_groups()
        
        for group, commands in command_groups.items():
            # Create group panel
            table = Table(box=SQUARE, show_header=False)
            table.add_column(f"[{PRIMARY_BLUE}]Command[/{PRIMARY_BLUE}]")
            table.add_column(f"[{PRIMARY_BLUE}]Description[/{PRIMARY_BLUE}]")
            
            for cmd, desc in commands:
                table.add_row(
                    f"[{SECONDARY_BLUE}]{cmd}[/{SECONDARY_BLUE}]",
                    f"[{WHITE}]{desc}[/{WHITE}]"
                )
            
            self.console.print(Panel(
                table,
                title=f"[{WHITE}]{group}[/{WHITE}]",
                box=SQUARE
            ))
            self.console.print()
    
    def emptyline(self):
        """Do nothing on empty line"""
        pass
    
    def default(self, line):
        """Handle unknown commands"""
        self.console.print(f"[red]Unknown command: {line}[/red]")
        self.console.print("Type 'help' or '?' to list available commands.")
    
    def do_h(self, arg):
        """Shortcut for help command"""
        return self.do_help(arg)
    
    def do_q(self, arg):
        """Shortcut for exit"""
        return self.do_exit(arg)
    
    def do_l(self, arg):
        """Shortcut for list"""
        return self.do_list(arg)
    
    def do_a(self, arg):
        """Shortcut for add"""
        return self.do_add(arg)
    
    def do_s(self, arg):
        """Shortcut for scan"""
        return self.do_scan(arg)
    
    def do_c(self, arg):
        """Shortcut for clear"""
        return self.do_clear(arg)
    
    def do_add(self, arg):
        """Add a new target: add <alias> <type> <target> (shortcut: a)
        Examples: 
          add site1 domain example.com
          add user1 username john_doe
          a work domain company.com"""
        try:
            alias, target_type, target = arg.split()
            if target_type not in ["domain", "username"]:
                self.console.print("[red]Error: Type must be 'domain' or 'username'[/red]")
                return
            
            if alias in self.session.targets:
                self.console.print(f"[red]Error: Alias '{alias}' already exists[/red]")
                return
            
            self.session.add_target(alias, target_type, target)
            self.console.print(f"[green]Added {target_type} '{target}' with alias '{alias}'[/green]")
        except ValueError:
            self.console.print("[red]Error: Please provide <alias> <type> <target>[/red]")
            self.console.print("Example: add site1 domain example.com")
    
    def do_scan(self, arg):
        """Scan a target: scan <alias> [scan_type] (shortcut: s)
        Examples:
          scan site1         (runs full scan)
          scan site1 ports   (port scan only)
          scan site1 dns     (DNS scan only)
          s user1           (username scan)
        
        Domain scan types:
          - dns    : DNS records and enumeration
          - ports  : Port scanning and service detection
          - whois  : WHOIS information
          - all    : Full reconnaissance (default)"""
        try:
            parts = arg.split()
            if not parts:
                self.console.print("[red]Error: Please provide target alias[/red]")
                return

            alias = parts[0]
            scan_type = parts[1] if len(parts) > 1 else "all"

            if alias not in self.session.targets:
                self.console.print(f"[red]Error: Alias '{alias}' not found. Add it first with 'add' command.[/red]")
                return
            
            target_info = self.session.targets[alias]
            target = target_info["value"]

            if target_info["type"] == "domain":
                if scan_type not in ["ports", "dns", "whois", "all"]:
                    self.console.print("[red]Error: Invalid scan type for domain[/red]")
                    self.console.print("Available types: ports, dns, whois, all")
                    return

                scanner = DomainScanner(
                    timeout=self.session.timeout,
                    proxy=self.session.proxy,
                    top_ports=self.session.top_ports,
                    wordlist=self.session.wordlist,
                    dns_server=self.session.dns_server
                )
                
                scan_msg = f"[bold blue]Scanning {target} ({alias})..."        
                if scan_type == "ports":
                    with self.console.status(f"{scan_msg}\n[dim]Running port scan...[/dim]"):
                        result = scanner.scan_ports(target)
                elif scan_type == "dns":
                    with self.console.status(f"{scan_msg}\n[dim]Gathering DNS records...[/dim]"):
                        result = scanner.scan_dns(target)
                elif scan_type == "whois":
                    with self.console.status(f"{scan_msg}\n[dim]Fetching WHOIS information...[/dim]"):
                        result = scanner.scan_whois(target)
                elif scan_type == "all":
                    with self.console.status(f"{scan_msg}\n[dim]Running full reconnaissance...[/dim]"):
                        result = scanner.scan(target)
                
                # Save results for all scan types
                self._save_result(target, scan_type, result)
            else:
                # Handle username scanning
                scanner = UsernameScanner(
                    timeout=self.session.timeout,
                    proxy=self.session.proxy,
                    retries=self.session.retries
                )
                
                result = scanner.scan(target)
                
                # Results will be displayed by the scanner itself
                self._save_result(target, "username", result)
                
                # Show completion message
                if not "error" in result:
                    self.console.print(Panel(
                        f"[white]Scan complete. Results saved to: {self.session.output_dir}[/white]",
                        box=SQUARE,
                        style=f"on {PRIMARY_BLUE}"
                    ))
        except ValueError:
            self.console.print("[red]Error: Please provide both scan type and target[/red]")
    
    def do_list(self, arg):
        """List all targets (shortcut: l)"""
        if not self.session.targets:
            self.console.print("[yellow]No targets added yet[/yellow]")
            return
        
        table = Table(title="Targets", box=ROUNDED)
        table.add_column("Alias", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Target", style="yellow")
        table.add_column("Last Scan", style="blue")
        
        for alias, info in self.session.targets.items():
            last_scan = info.get("last_scan", "Never")
            table.add_row(alias, info["type"], info["value"], str(last_scan))
        
        self.console.print(table)
    
    def do_clear(self, arg):
        """Clear all targets (shortcut: c)"""
        self.session.targets.clear()
        self.console.print("[green]All targets cleared[/green]")
    
    def do_exit(self, arg):
        """Exit the SPYLO shell (shortcut: q)"""
        self.console.print("[yellow]Goodbye![/yellow]")
        return True
    
    def _save_result(self, target, scan_type, result):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.session.targets[target]["last_scan"] = ts
        
        meta = {
            "target": target,
            "scan_type": scan_type,
            "timestamp_utc": ts
        }
        
        # Save results
        ensure_dir(self.session.output_dir)
        save_reports(meta, result, self.session.output_dir, ["json", "table"])
        print_table_summary(meta, result)
        
        self.console.print(f"\n[green]Results saved to: {self.session.output_dir}[/green]")

def main():
    console = Console()
    try:
        # Create and run the shell
        shell = SPYLOShell()
        while True:
            try:
                shell.cmdloop()
                break
            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'exit' or 'q' to quit[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                console.print("[yellow]Continuing...[/yellow]")
        return 0
    except Exception as e:
        console.print(f"[red]Fatal Error: {e}[/red]")
        return 1
    
    # Welcome message
    console.print(Panel(
        "[bold cyan]Welcome to SPYLO![/bold cyan]\n" +
        "[dim]An advanced OSINT framework for reconnaissance[/dim]",
        box=ROUNDED,
        style="blue"
    ))
    
    # Basic Configuration
    show_section_header("📋 Basic Configuration")
    scan_type = get_user_input(
        "Select scan type",
        choices=["username", "domain"],
        default="domain"
    )
    target = get_user_input(f"Enter {scan_type} to scan")
    output_dir = get_user_input("Enter output directory", default="out")
    output_formats = get_user_input(
        "Enter output formats",
        default="table,json",
        choices=["table", "json", "csv", "md", "table,json", "table,json,csv"]
    )
    
    # Advanced Options with visual grouping
    show_section_header("⚙️ Advanced Options")
    proxy = get_user_input("Enter proxy URL (optional)", default=None)
    timeout = int(get_user_input("Enter request timeout in seconds", default="15"))
    retries = int(get_user_input("Enter number of retries", default="2"))
    
    # Module specific options with visual grouping
    if scan_type == "username":
        show_section_header("👤 Username Scan Configuration")
        concurrency = int(get_user_input("Enter concurrency level", default="50"))
    else:
        show_section_header("🌐 Domain Scan Configuration")
        wordlist = get_user_input("Enter subdomain wordlist path", default="sub.txt")
        
        # Port scanning options in a submenu
        console.print("\n[bold cyan]Port Scanning Options:[/bold cyan]")
        top_ports = get_user_input(
            "Enter comma-separated ports to scan",
            default="80,443,22,25,53,110,143,587,993,995,2083,2087,3306,3389,444,465,8080,8443"
        )
        no_scan_ports = get_boolean_input("Disable port scanning", default=False)
        
        # DNS options in a submenu
        console.print("\n[bold cyan]DNS Options:[/bold cyan]")
        no_axfr = get_boolean_input("Skip AXFR zone-transfer attempts", default=False)
        dns_server = get_user_input("Enter specific DNS server (optional)", default=None)
    
    # Show configuration summary
    show_section_header("📊 Configuration Summary")
    options = {
        "Scan Type": scan_type,
        "Target": target,
        "Output Directory": output_dir,
        "Output Formats": output_formats,
        "Proxy": proxy or "Not set",
        "Timeout": f"{timeout}s",
        "Retries": retries
    }
    
    if scan_type == "username":
        options["Concurrency"] = concurrency
    else:
        options.update({
            "Wordlist": wordlist,
            "Port Scanning": "Disabled" if no_scan_ports else "Enabled",
            "AXFR Attempts": "Disabled" if no_axfr else "Enabled",
            "DNS Server": dns_server or "Default"
        })
    
    console.print(create_options_table("Scan Configuration", options))
    
    if not Confirm.ask("\n[bold cyan]Start scan with these settings?[/bold cyan]", default=True):
        console.print("[yellow]Scan cancelled by user[/yellow]")
        return
    
    # Create args namespace
    class Args:
        pass
    
    args = Args()
    args.type = scan_type
    args.target = target
    args.output = output_dir
    args.format = output_formats
    args.proxy = proxy
    args.timeout = timeout
    args.retries = retries
    
    if scan_type == "username":
        args.concurrency = concurrency
    else:
        args.wordlist = wordlist
        args.top_ports = top_ports
        args.no_scan_ports = no_scan_ports
        args.no_axfr = no_axfr
        args.dns_server = dns_server
    
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ensure_dir(args.output)
    
    # Show scan initialization
    console.print(Panel(
        f"[bold green]Starting {scan_type.title()} Scan[/bold green]\n" +
        f"[dim]Target: [cyan]{args.target}[/cyan]\n" +
        f"Time: [cyan]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/cyan][/dim]",
        title="[bold]Scan Information[/bold]",
        box=ROUNDED
    ))

    result = None
    meta = {
        "module": args.type,
        "target": args.target,
        "timestamp_utc": ts,
        "tool": "osint-mega-tool",
        "version": "0.1.0",
    }

    with console.status(f"[bold blue]Scanning {args.target}...", spinner="dots"):
        if args.type == "username":
            scanner = UsernameScanner(timeout=args.timeout,
                                    concurrency=args.concurrency,
                                    retries=args.retries,
                                    proxy=args.proxy)
            result = scanner.scan(args.target)
        elif args.type == "domain":
            scanner = DomainScanner(timeout=args.timeout,
                                  proxy=args.proxy,
                                  no_axfr=args.no_axfr,
                                  no_scan_ports=args.no_scan_ports,
                                  top_ports=args.top_ports,
                                  wordlist=args.wordlist,
                                  dns_server=args.dns_server)
            result = scanner.scan(args.target)

    # Show completion message
    console.print("\n[bold green]✓ Scan completed successfully![/bold green]\n")

    # Reporting
    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    
    with console.status("[bold blue]Generating reports...", spinner="dots"):
        print_table_summary(meta, result)
        save_reports(meta, result, out_dir=args.output, formats=formats)
    
    # Show final summary
    console.print(Panel(
        f"[bold green]Scan Complete![/bold green]\n" +
        f"[dim]Results saved to: [cyan]{args.output}[/cyan]\n" +
        f"Output formats: [cyan]{', '.join(formats)}[/cyan][/dim]",
        title="[bold]Scan Summary[/bold]",
        box=ROUNDED
    ))


if __name__ == "__main__":
    sys.exit(main())
