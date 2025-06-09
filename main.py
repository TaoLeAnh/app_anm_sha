#!/usr/bin/env python3
"""
Personal Password Manager - Main Application Entry Point

A secure personal password manager application using Python and Tkinter.
Features include:
- AES-256 encryption with PBKDF2 key derivation
- Master password protection with strength validation
- Secure account storage and management
- Password generation with customizable options
- Import/export functionality
- Search and categorization
- Session timeout and security features

Author: Password Manager Application
Version: 1.0.0
License: MIT
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from setup_master import MasterPasswordSetup
    from ui.login_window import LoginWindow
    from ui.main_window import MainWindow
    from password_manager import PasswordManager
except ImportError as e:
    print(f"Failed to import required modules: {e}")
    print("Please ensure all required dependencies are installed.")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)


class PasswordManagerApp:
    """Main application controller."""
    
    def __init__(self):
        self.password_manager = None
        self.master_password = None
    
    def run(self):
        """Run the complete application workflow."""
        try:
            # Check if this is the first run
            setup = MasterPasswordSetup()
            
            if setup.needs_setup():
                print("First-time setup detected. Creating master password...")
                master_password = setup.show_setup_window()
                
                if not master_password:
                    print("Setup cancelled. Exiting application.")
                    return
                
                self.master_password = master_password
                print("Master password setup completed successfully!")
            
            else:
                # Show login window
                print("Existing installation detected. Showing login window...")
                login = LoginWindow()
                success, master_password = login.show_login_window()
                
                if not success:
                    print("Login cancelled or failed. Exiting application.")
                    return
                
                self.master_password = master_password
                print("Login successful!")
            
            # Initialize password manager with master password
            print("Initializing password manager...")
            self.password_manager = PasswordManager(self.master_password)
            
            # Show main application window
            print("Starting main application...")
            main_window = MainWindow(self.password_manager)
            main_window.show()
            
        except Exception as e:
            print(f"Application error: {e}")
            print(f"An unexpected error occurred: {str(e)}")
            print("The application will now exit.")
            sys.exit(1)


def check_dependencies():
    """Check if all required dependencies are available."""
    missing_deps = []
    
    try:
        import cryptography
    except ImportError:
        missing_deps.append("cryptography")
    
    try:
        import pyperclip
    except ImportError:
        missing_deps.append("pyperclip")
    
    try:
        from PIL import Image
    except ImportError:
        missing_deps.append("pillow")
    
    if missing_deps:
        print("Missing required dependencies:")
        for dep in missing_deps:
            print(f"  - {dep}")
        print("\nPlease install missing dependencies with:")
        print("pip install -r requirements.txt")
        return False
    
    return True


def show_welcome_message():
    """Show welcome message and application information."""
    print("=" * 60)
    print("           PERSONAL PASSWORD MANAGER v1.0.0")
    print("=" * 60)
    print()
    print("A secure password manager for personal use.")
    print("Features:")
    print("  • AES-256 encryption with PBKDF2 key derivation")
    print("  • Master password protection")
    print("  • Secure password generation")
    print("  • Account categorization and search")
    print("  • Import/export functionality")
    print("  • Session timeout and security features")
    print()
    print("Starting application...")
    print()


def main():
    """Main entry point."""
    # Show welcome message
    show_welcome_message()
    
    # Check dependencies
    if not check_dependencies():
        input("Press Enter to exit...")
        sys.exit(1)
    
    # Create and run the application
    try:
        app = PasswordManagerApp()
        app.run()
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user.")
        sys.exit(0)
    
    except Exception as e:
        print(f"Fatal error: {e}")
        input("Press Enter to exit...")
        sys.exit(1)
    
    print("Application closed. Thank you for using Password Manager!")


if __name__ == "__main__":
    main()
