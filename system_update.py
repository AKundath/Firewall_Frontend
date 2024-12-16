#!/usr/bin/env python3
import subprocess
import os
import sys

class SystemUpdater:
    def __init__(self):
        if os.geteuid() != 0:
            print("This script must be run as root. Please use sudo.")
            sys.exit(1)

    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')

    def run_command(self, command, show_output=True):
        """Run a command and optionally show its output."""
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output and show_output:
                    print(output.strip())
            
            return process.returncode == 0
        except subprocess.CalledProcessError:
            return False

    def update_system(self):
        """Update system packages."""
        print("\nUpdating package lists...")
        if not self.run_command(['apt', 'update']):
            return False
        
        print("\nUpgrading packages...")
        return self.run_command(['apt', 'upgrade', '-y'])

    def display_menu(self):
        """Display the update menu."""
        self.clear_screen()
        print("=== System Update Menu ===")
        print("\n1. Update and upgrade system")
        print("2. Back to main menu")
        return input("\nEnter your choice (1-2): ")

    def run(self):
        """Run the update menu loop."""
        while True:
            choice = self.display_menu()
            
            if choice == '1':
                if self.update_system():
                    print("\nSystem update completed successfully")
                else:
                    print("\nSystem update failed")
                input("\nPress Enter to continue...")
                
            elif choice == '2':
                break
            
            else:
                print("\nInvalid choice. Please try again.")
                input("\nPress Enter to continue...")

if __name__ == "__main__":
    updater = SystemUpdater()
    updater.run()