#!/usr/bin/env python3
import subprocess
import os
import sys

class IPManager:
    def __init__(self):
        # Check if script is run with root privileges
        if os.geteuid() != 0:
            print("This script must be run with root. Please use sudo.")
            sys.exit(1)

    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')

    def validate_ip(self, ip_address):
        """Basic IP address validation."""
        try:
            parts = ip_address.split('.')
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except (ValueError, TypeError):
            return False

    def allow_ip(self, ip_address):
        """Allow an IP address."""
        try:
            if not self.validate_ip(ip_address):
                print("\nError: Invalid IP address format")
                return False
            
            subprocess.run(['ufw', 'allow', 'from', ip_address], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def deny_ip(self, ip_address):
        """Deny an IP address."""
        try:
            if not self.validate_ip(ip_address):
                print("\nError: Invalid IP address format")
                return False
            
            subprocess.run(['ufw', 'deny', 'from', ip_address], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def delete_rules(self, ip_address):
        """Delete rules for an IP address."""
        try:
            if not self.validate_ip(ip_address):
                print("\nError: Invalid IP address format")
                return False
            
            # Try to delete both allow and deny rules
            subprocess.run(['ufw', 'delete', 'allow', 'from', ip_address], check=True)
            subprocess.run(['ufw', 'delete', 'deny', 'from', ip_address], check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def display_menu(self):
        """Display the main menu."""
        self.clear_screen()
        print("=== IP Address Management ===")
        print("\n1. Allow IP Address")
        print("2. Deny IP Address")
        print("3. Delete IP Rules")
        print("4. Show Current Rules")
        print("5. Back to main menu")
        return input("\nEnter your choice (1-5): ")

    def run(self):
        """Run the main program loop."""
        while True:
            choice = self.display_menu()
            
            if choice == '1':
                ip_address = input("\nEnter IP address to allow (e.g., 192.168.1.100): ")
                if self.allow_ip(ip_address):
                    print(f"\nSuccessfully allowed {ip_address}")
                else:
                    print(f"\nFailed to allow {ip_address}")
                input("\nPress Enter to continue...")
                
            elif choice == '2':
                ip_address = input("\nEnter IP address to deny (e.g., 192.168.1.100): ")
                if self.deny_ip(ip_address):
                    print(f"\nSuccessfully denied {ip_address}")
                else:
                    print(f"\nFailed to deny {ip_address}")
                input("\nPress Enter to continue...")
                
            elif choice == '3':
                ip_address = input("\nEnter IP address to delete rules for: ")
                if self.delete_rules(ip_address):
                    print(f"\nSuccessfully deleted rules for {ip_address}")
                else:
                    print(f"\nFailed to delete rules for {ip_address}")
                input("\nPress Enter to continue...")
                
            elif choice == '4':
                self.clear_screen()
                print("\nCurrent UFW Rules:")
                subprocess.run(['ufw', 'status', 'verbose'])
                input("\nPress Enter to continue...")
                
            elif choice == '5':
                break
            
            else:
                print("\nInvalid choice. Please try again.")
                input("\nPress Enter to continue...")

def main():
    manager = IPManager()
    manager.run()

if __name__ == "__main__":
    main()