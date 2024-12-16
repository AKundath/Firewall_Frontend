#!/usr/bin/env python3
import subprocess
import sys
import os
import time
from typing import List, Dict, Union

class NetworkConfigManager:
    def __init__(self):
        # Check if script is run with root privileges
        if os.geteuid() != 0:
            print("This script must be run with root. Please use sudo.")
            sys.exit(1)
        
        # Common services and their default ports
        self.common_services = {
            'HTTP': 80,
            'HTTPS': 443,
            'SSH': 22,
            'FTP': 21,
            'SMTP': 25,
            'SMTP (TLS)': 587,
            'POP3': 110,
            'POP3 (SSL)': 995,
            'IMAP': 143,
            'IMAP (SSL)': 993,
            'DNS': 53,
            'MySQL': 3306,
            'PostgreSQL': 5432,
            'MongoDB': 27017,
            'Terraria Server': 7777
        }

    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')

    def check_ufw_status(self) -> Dict[str, Union[bool, str]]:
        """Check UFW status and return details."""
        try:
            status = subprocess.check_output(['ufw', 'status', 'verbose']).decode()
            is_active = 'Status: active' in status
            return {
                'active': is_active,
                'status_details': status
            }
        except subprocess.CalledProcessError as e:
            return {
                'active': False,
                'status_details': f"Error: {str(e)}"
            }

    def enable_ufw(self) -> bool:
        """Enable UFW firewall."""
        try:
            subprocess.run(['ufw', '--force', 'enable'], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def disable_ufw(self) -> bool:
        """Disable UFW firewall."""
        try:
            subprocess.run(['ufw', 'disable'], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def add_rule(self, port: int, protocol: str = 'tcp', action: str = 'allow') -> bool:
        """Add a new firewall rule."""
        try:
            subprocess.run(['ufw', action, f'{port}/{protocol}'], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def delete_rule(self, port: int, protocol: str = 'tcp', action: str = 'allow') -> bool:
        """Delete an existing firewall rule."""
        try:
            # Warning for SSH port
            if port == 22 and protocol == 'tcp':
                print("\n⚠️  WARNING: You are about to disable the SSH firewall rule!")
                print("This could lock you out of remote access to this server.")
                confirm = input("Are you sure you want to continue? (yes/no): ").lower()
                if confirm != 'yes':
                    print("Operation cancelled.")
                    return False
                    
            subprocess.run(['ufw', 'delete', action, f'{port}/{protocol}'], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def get_network_stats(self) -> Dict[str, str]:
        """Get network interface statistics."""
        stats = {}
        try:
            stats['interfaces'] = subprocess.check_output(['ip', 'link', 'show']).decode()
            stats['ip_addresses'] = subprocess.check_output(['ip', 'addr', 'show']).decode()
            stats['routing'] = subprocess.check_output(['ip', 'route']).decode()
            stats['connections'] = subprocess.check_output(['ss', '-tuln']).decode()
            return stats
        except subprocess.CalledProcessError as e:
            print(f"Error getting network stats: {str(e)}")
            return {}

    def display_menu(self):
        """Display the main menu."""
        self.clear_screen()
        print("=== Firewall Management ===")
        print("\nMain Menu:")
        print("1. Show Firewall Status")
        print("2. Enable Firewall")
        print("3. Disable Firewall")
        print("4. Manage Ports")
        print("5. Show Network Statistics")
        print("6. Back to Main Menu")
        return input("\nEnter your choice (1-6): ")

    def display_services_menu(self):
        """Display the services menu."""
        self.clear_screen()
        print("=== Common Services ===")
        print("\nAvailable services:")
        for i, (service, port) in enumerate(self.common_services.items(), 1):
            print(f"{i}. {service} (Port {port})")
        print(f"{len(self.common_services) + 1}. Custom port")
        print(f"{len(self.common_services) + 2}. Back to previous menu")
        return input(f"\nEnter your choice (1-{len(self.common_services) + 2}): ")

    def handle_port_management(self):
        """Handle port management menu."""
        while True:
            self.clear_screen()
            print("=== Port Management ===")
            print("\n1. Open port for service")
            print("2. Close port")
            print("3. Back to previous menu")
            
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == '1':
                service_choice = self.display_services_menu()
                try:
                    service_idx = int(service_choice) - 1
                    if service_idx == len(self.common_services):
                        # Custom port
                        port = int(input("Enter the port number: "))
                        protocol = input("Enter protocol (tcp/udp) [tcp]: ").lower() or 'tcp'
                    elif service_idx < len(self.common_services):
                        service = list(self.common_services.keys())[service_idx]
                        port = self.common_services[service]
                        protocol = 'tcp'
                    else:
                        continue

                    if self.add_rule(port, protocol):
                        print(f"\nSuccessfully opened port {port}/{protocol}")
                    else:
                        print(f"\nFailed to open port {port}/{protocol}")
                    
                except ValueError:
                    print("\nInvalid input. Please enter a number.")
                input("\nPress Enter to continue...")
                
            elif choice == '2':
                try:
                    port = int(input("Enter the port number to close: "))
                    protocol = input("Enter protocol (tcp/udp) [tcp]: ").lower() or 'tcp'
                    
                    if self.delete_rule(port, protocol):
                        print(f"\nSuccessfully closed port {port}/{protocol}")
                    else:
                        print(f"\nFailed to close port {port}/{protocol}")
                except ValueError:
                    print("\nInvalid input. Please enter a number.")
                input("\nPress Enter to continue...")
                
            elif choice == '3':
                break

    def run(self):
        """Run the main program loop."""
        while True:
            choice = self.display_menu()
            
            if choice == '1':
                self.clear_screen()
                status = self.check_ufw_status()
                print("\nFirewall Status:")
                print(status['status_details'])
                input("\nPress Enter to continue...")
                
            elif choice == '2':
                if self.enable_ufw():
                    print("\nFirewall has been enabled successfully.")
                else:
                    print("\nFailed to enable firewall.")
                input("\nPress Enter to continue...")
                
            elif choice == '3':
                if self.disable_ufw():
                    print("\nFirewall has been disabled successfully.")
                else:
                    print("\nFailed to disable firewall.")
                input("\nPress Enter to continue...")
                
            elif choice == '4':
                self.handle_port_management()
                
            elif choice == '5':
                self.clear_screen()
                stats = self.get_network_stats()
                if stats:
                    print("\n=== Network Interfaces ===")
                    print(stats['interfaces'])
                    print("\n=== IP Addresses ===")
                    print(stats['ip_addresses'])
                    print("\n=== Routing Table ===")
                    print(stats['routing'])
                    print("\n=== Active Connections ===")
                    print(stats['connections'])
                input("\nPress Enter to continue...")
                
            elif choice == '6':
                break
            
            else:
                print("\nInvalid choice. Please try again.")
                input("\nPress Enter to continue...")

if __name__ == "__main__":
    manager = NetworkConfigManager()
    manager.run()