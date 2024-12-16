#!/usr/bin/env python3
import subprocess
import os
import sys
from datetime import datetime

class SnapshotManager:
    def __init__(self):
        # Check for root privileges only when running standalone
        if __name__ == "__main__" and os.geteuid() != 0:
            print("This script must be run as root. Please use sudo.")
            sys.exit(1)
            
        self.timeshift_path = '/usr/bin/timeshift'
        self.config_path = '/etc/timeshift'

    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('clear' if os.name != 'nt' else 'cls')

    def run_command(self, command, show_output=True):
        """Run a command and capture both stdout and stderr."""
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout = []
            stderr = []
            
            # Read stdout and stderr
            while True:
                outputs = [process.stdout.readline(), process.stderr.readline()]
                
                if outputs[0] == '' and outputs[1] == '' and process.poll() is not None:
                    break
                    
                if outputs[0] and show_output:
                    print(outputs[0].strip())
                    stdout.append(outputs[0])
                if outputs[1] and show_output:
                    print(f"Error: {outputs[1].strip()}")
                    stderr.append(outputs[1])
            
            # Store the output for potential debugging
            self.last_command_output = {
                'stdout': ''.join(stdout),
                'stderr': ''.join(stderr),
                'returncode': process.returncode
            }
            
            return process.returncode == 0
            
        except Exception as e:
            print(f"Command execution failed: {str(e)}")
            self.last_command_output = {
                'stdout': '',
                'stderr': str(e),
                'returncode': -1
            }
            return False

    def check_timeshift_installation(self):
        """Check if Timeshift is installed and configured."""
        if not os.path.exists(self.timeshift_path):
            print("\nTimeshift is not installed. Installing now...")
            if not self.run_command(['apt', 'install', 'timeshift', '-y']):
                print("Failed to install Timeshift")
                return False
        
        if not os.path.exists(self.config_path):
            print("\nTimeshift is not configured. Please run 'sudo timeshift --setup' first.")
            return False
            
        return True

    def create_snapshot(self, description=None):
        """Create a Timeshift snapshot."""
        try:
            if not self.check_timeshift_installation():
                return False
                
            if description is None:
                description = f"Auto-snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            print("\nCreating system snapshot...")
            command = ['timeshift', '--create', '--comments', description, '--verbose']
            success = self.run_command(command)
            
            # Check for specific error patterns in the output
            if self.last_command_output.get('stderr') and (
                'rsync returned an error' in self.last_command_output['stderr'] or 
                'Failed to create new snapshot' in self.last_command_output['stderr']
            ):
                print("\nSnapshot creation failed - rsync error detected")
                print("Please run 'sudo timeshift --setup' to verify backup location")
                return False
                
            # Check if the output contains successful completion markers
            if self.last_command_output.get('stdout') and 'Removing snapshots (incomplete)' in self.last_command_output['stdout']:
                print("\nSnapshot was incomplete and was cleaned up")
                print("Please verify backup location has enough space")
                return False
                
            if not success:
                print("\nSnapshot creation failed - unknown error")
                return False
                
            return True
                
        except Exception as e:
            print(f"Error creating snapshot: {str(e)}")
            return False

    def list_snapshots(self):
        """List existing snapshots."""
        try:
            if not self.check_timeshift_installation():
                return False
                
            print("\nExisting snapshots:")
            return self.run_command(['timeshift', '--list', '--verbose'])
        except Exception as e:
            print(f"Error listing snapshots: {str(e)}")
            return False

    def display_menu(self):
        """Display the snapshot menu."""
        self.clear_screen()
        print("=== System Snapshot Menu ===")
        print("\n1. Create snapshot with default name")
        print("2. Create snapshot with custom description")
        print("3. List existing snapshots")
        print("4. Back to main menu")
        return input("\nEnter your choice (1-4): ")

    def run(self):
        """Run the snapshot menu loop."""
        while True:
            choice = self.display_menu()
            
            if choice == '1':
                success = self.create_snapshot()
                if success:
                    print("\nSnapshot created and verified successfully")
                else:
                    print("\nSnapshot creation failed or was incomplete")
                input("\nPress Enter to continue...")
                
            elif choice == '2':
                description = input("\nEnter snapshot description: ")
                success = self.create_snapshot(description)
                if success:
                    print("\nSnapshot created and verified successfully")
                else:
                    print("\nSnapshot creation failed or was incomplete")
                input("\nPress Enter to continue...")
            
            elif choice == '3':
                self.list_snapshots()
                input("\nPress Enter to continue...")
                
            elif choice == '4':
                break

if __name__ == "__main__":
    snapshot = SnapshotManager()
    snapshot.run()