"""
Dialog windows for the password manager application.
Includes add account, password generator, and settings dialogs.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyperclip
from typing import Optional, Dict, Any
import os
import json
import base64
from cryptography.fernet import Fernet


class AddAccountDialog:
    """Dialog for adding or editing accounts."""
    
    def __init__(self, parent, password_manager, categories: list, account_data: dict = None):
        self.parent = parent
        self.password_manager = password_manager
        self.categories = categories
        self.account_data = account_data
        self.result = None
        self.window = None
        
        # Variables
        self.service_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.url_var = tk.StringVar()
        self.notes_var = tk.StringVar()
        self.category_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar()
        
        # Fill existing data if editing
        if account_data:
            self.service_var.set(account_data.get('service', ''))
            self.username_var.set(account_data.get('username', ''))
            self.password_var.set(account_data.get('password', ''))
            self.url_var.set(account_data.get('url', ''))
            self.notes_var.set(account_data.get('notes', ''))
            self.category_var.set(account_data.get('category', 'Other'))
    
    def show(self) -> Optional[Dict[str, str]]:
        """Show the dialog and return the result."""
        self.window = tk.Toplevel(self.parent)
        self.window.title("Add Account" if not self.account_data else "Edit Account")
        self.window.geometry("500x600")
        self.window.resizable(False, False)
        
        # Center the window
        self._center_window()
        
        # Make modal
        self.window.transient(self.parent)
        self.window.grab_set()
        
        self._create_widgets()
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self._on_cancel)
        
        # Wait for window to be destroyed
        self.window.wait_window()
        
        return self.result
    
    def _center_window(self):
        """Center the window on parent."""
        self.window.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (500 // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (600 // 2)
        self.window.geometry(f"500x600+{x}+{y}")
    
    def _create_widgets(self):
        """Create the dialog widgets."""
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title = "Add New Account" if not self.account_data else "Edit Account"
        title_label = ttk.Label(main_frame, text=title, font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Service name
        ttk.Label(main_frame, text="Service Name *", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        service_entry = ttk.Entry(main_frame, textvariable=self.service_var, font=('Arial', 11))
        service_entry.pack(fill=tk.X, pady=(5, 10))
        
        # Username/Email
        ttk.Label(main_frame, text="Username/Email *", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        username_entry = ttk.Entry(main_frame, textvariable=self.username_var, font=('Arial', 11))
        username_entry.pack(fill=tk.X, pady=(5, 10))
        
        # Password section
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(password_frame, text="Password *", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        password_input_frame = ttk.Frame(password_frame)
        password_input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.password_entry = ttk.Entry(password_input_frame, textvariable=self.password_var, 
                                       show="*", font=('Arial', 11))
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        show_check = ttk.Checkbutton(password_input_frame, text="Show", 
                                   variable=self.show_password_var,
                                   command=self._toggle_password_visibility)
        show_check.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Password buttons
        password_btn_frame = ttk.Frame(password_frame)
        password_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(password_btn_frame, text="Generate Password", 
                  command=self._generate_password).pack(side=tk.LEFT)
        ttk.Button(password_btn_frame, text="Check Strength", 
                  command=self._check_strength).pack(side=tk.LEFT, padx=(10, 0))
        
        # URL
        ttk.Label(main_frame, text="Website URL", font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(10, 0))
        url_entry = ttk.Entry(main_frame, textvariable=self.url_var, font=('Arial', 11))
        url_entry.pack(fill=tk.X, pady=(5, 10))
        
        # Category
        ttk.Label(main_frame, text="Category", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        category_combo = ttk.Combobox(main_frame, textvariable=self.category_var, 
                                    values=self.categories, font=('Arial', 11), state="readonly")
        category_combo.pack(fill=tk.X, pady=(5, 10))
        if not self.category_var.get():
            category_combo.set("Other")
        
        # Notes
        ttk.Label(main_frame, text="Notes", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        self.notes_text = tk.Text(main_frame, height=5, wrap=tk.WORD, font=('Arial', 10))
        self.notes_text.pack(fill=tk.X, pady=(5, 20))
        if self.notes_var.get():
            self.notes_text.insert(1.0, self.notes_var.get())
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT, padx=(10, 0))
        save_text = "Save" if self.account_data else "Add Account"
        ttk.Button(button_frame, text=save_text, command=self._on_save).pack(side=tk.RIGHT)
        
        # Focus on service entry
        service_entry.focus_set()
        
        # Bind Enter key
        self.window.bind('<Return>', lambda e: self._on_save())
    
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def _generate_password(self):
        """Show password generator dialog."""
        generator = PasswordGeneratorDialog(self.window, self.password_manager)
        password = generator.show()
        if password:
            self.password_var.set(password)
    
    def _check_strength(self):
        """Check password strength."""
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password first.")
            return
        
        strength = self.password_manager.check_password_strength(password)
        
        feedback_text = f"Password Strength: {strength['strength']} ({strength['score']}/100)\n\n"
        if strength['feedback']:
            feedback_text += "Suggestions for improvement:\n"
            for suggestion in strength['feedback']:
                feedback_text += f"• {suggestion}\n"
        else:
            feedback_text += "This is a strong password!"
        
        messagebox.showinfo("Password Strength", feedback_text)
    
    def _validate_data(self) -> bool:
        """Validate the entered data."""
        if not self.service_var.get().strip():
            messagebox.showerror("Error", "Service name is required.")
            return False
        
        if not self.username_var.get().strip():
            messagebox.showerror("Error", "Username/Email is required.")
            return False
        
        if not self.password_var.get():
            messagebox.showerror("Error", "Password is required.")
            return False
        
        return True
    
    def _on_save(self):
        """Handle save button click."""
        if not self._validate_data():
            return
        
        try:
            self.result = {
                'service': self.service_var.get().strip(),
                'username': self.username_var.get().strip(),
                'password': self.password_var.get(),
                'url': self.url_var.get().strip(),
                'notes': self.notes_text.get(1.0, tk.END).strip(),
                'category': self.category_var.get()
            }
            
            # Destroy window after setting result
            if self.window:
                self.window.destroy()
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save data: {str(e)}")
    
    def _on_cancel(self):
        """Handle cancel button click."""
        self.result = None
        if self.window:
            self.window.destroy()


class PasswordGeneratorDialog:
    """Dialog for generating secure passwords."""
    
    def __init__(self, parent, password_manager):
        self.parent = parent
        self.password_manager = password_manager
        self.window = None
        self.result = None
        
        # Variables
        self.length_var = tk.IntVar(value=16)
        self.uppercase_var = tk.BooleanVar(value=True)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.numbers_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.exclude_similar_var = tk.BooleanVar(value=False)
        self.generated_password = tk.StringVar()
    
    def show(self) -> Optional[str]:
        """Show the password generator dialog."""
        self.window = tk.Toplevel(self.parent)
        self.window.title("Password Generator")
        self.window.geometry("450x500")
        self.window.resizable(False, False)
        
        # Center the window
        self._center_window()
        
        # Make modal
        self.window.transient(self.parent)
        self.window.grab_set()
        
        self._create_widgets()
        
        # Generate initial password
        self._generate_password()
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self._on_cancel)
        
        self.window.mainloop()
        
        return self.result
    
    def _center_window(self):
        """Center the window on parent."""
        self.window.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (450 // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (500 // 2)
        self.window.geometry(f"450x500+{x}+{y}")
    
    def _create_widgets(self):
        """Create the generator widgets."""
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Password Generator", font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Length setting
        length_frame = ttk.Frame(main_frame)
        length_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(length_frame, text="Password Length:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        length_input_frame = ttk.Frame(length_frame)
        length_input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.length_scale = ttk.Scale(length_input_frame, from_=8, to=128, 
                                    variable=self.length_var, orient=tk.HORIZONTAL,
                                    command=self._on_length_change)
        self.length_scale.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.length_label = ttk.Label(length_input_frame, text="16", font=('Arial', 10, 'bold'))
        self.length_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Character options
        options_frame = ttk.LabelFrame(main_frame, text="Character Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Checkbutton(options_frame, text="Uppercase letters (A-Z)", 
                       variable=self.uppercase_var, command=self._on_option_change).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Lowercase letters (a-z)", 
                       variable=self.lowercase_var, command=self._on_option_change).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Numbers (0-9)", 
                       variable=self.numbers_var, command=self._on_option_change).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Symbols (!@#$%^&*)", 
                       variable=self.symbols_var, command=self._on_option_change).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Exclude similar characters (0, O, l, 1, etc.)", 
                       variable=self.exclude_similar_var, command=self._on_option_change).pack(anchor=tk.W, pady=2)
        
        # Generated password
        password_frame = ttk.LabelFrame(main_frame, text="Generated Password", padding="10")
        password_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.password_display = tk.Text(password_frame, height=3, wrap=tk.WORD, 
                                      font=('Courier', 12), state=tk.DISABLED)
        self.password_display.pack(fill=tk.X, pady=(0, 10))
        
        password_btn_frame = ttk.Frame(password_frame)
        password_btn_frame.pack(fill=tk.X)
        
        ttk.Button(password_btn_frame, text="Generate New", 
                  command=self._generate_password).pack(side=tk.LEFT)
        ttk.Button(password_btn_frame, text="Copy to Clipboard", 
                  command=self._copy_password).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(password_btn_frame, text="Check Strength", 
                  command=self._check_strength).pack(side=tk.LEFT, padx=(10, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Use This Password", command=self._on_use).pack(side=tk.RIGHT)
    
    def _on_length_change(self, value):
        """Handle length scale change."""
        length = int(float(value))
        self.length_var.set(length)
        self.length_label.config(text=str(length))
        self._generate_password()
    
    def _on_option_change(self):
        """Handle character option change."""
        # Ensure at least one option is selected
        if not any([self.uppercase_var.get(), self.lowercase_var.get(), 
                   self.numbers_var.get(), self.symbols_var.get()]):
            self.lowercase_var.set(True)
        
        self._generate_password()
    
    def _generate_password(self):
        """Generate a new password."""
        try:
            password = self.password_manager.generate_password(
                length=self.length_var.get(),
                use_uppercase=self.uppercase_var.get(),
                use_lowercase=self.lowercase_var.get(),
                use_numbers=self.numbers_var.get(),
                use_symbols=self.symbols_var.get(),
                exclude_similar=self.exclude_similar_var.get()
            )
            
            self.generated_password.set(password)
            
            self.password_display.config(state=tk.NORMAL)
            self.password_display.delete(1.0, tk.END)
            self.password_display.insert(1.0, password)
            self.password_display.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
    
    def _copy_password(self):
        """Copy generated password to clipboard."""
        password = self.generated_password.get()
        if password:
            try:
                pyperclip.copy(password)
                messagebox.showinfo("Copied", "Password copied to clipboard!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")
    
    def _check_strength(self):
        """Check strength of generated password."""
        password = self.generated_password.get()
        if password:
            strength = self.password_manager.check_password_strength(password)
            
            feedback_text = f"Password Strength: {strength['strength']} ({strength['score']}/100)\n\n"
            if strength['feedback']:
                feedback_text += "Suggestions for improvement:\n"
                for suggestion in strength['feedback']:
                    feedback_text += f"• {suggestion}\n"
            else:
                feedback_text += "This is a strong password!"
            
            messagebox.showinfo("Password Strength", feedback_text)
    
    def _on_use(self):
        """Use the generated password."""
        self.result = self.generated_password.get()
        self.window.destroy()
    
    def _on_cancel(self):
        """Cancel password generation."""
        self.window.destroy()


class SettingsDialog:
    """Settings dialog for application configuration."""
    
    def __init__(self, parent, password_manager):
        self.parent = parent
        self.password_manager = password_manager
        self.window = None
        self.settings = password_manager.get_settings()
        
        # Variables
        self.auto_backup_var = tk.BooleanVar(value=self.settings.get('auto_backup', True))
        self.session_timeout_var = tk.IntVar(value=self.settings.get('session_timeout', 1800) // 60)
        self.clipboard_clear_var = tk.IntVar(value=self.settings.get('clipboard_clear_time', 30))
    
    def show(self):
        """Show the settings dialog."""
        self.window = tk.Toplevel(self.parent)
        self.window.title("Settings")
        self.window.geometry("400x350")
        self.window.resizable(False, False)
        
        # Center the window
        self._center_window()
        
        # Make modal
        self.window.transient(self.parent)
        self.window.grab_set()
        
        self._create_widgets()
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self._on_cancel)
        
        self.window.mainloop()
    
    def _center_window(self):
        """Center the window on parent."""
        self.window.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (400 // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (350 // 2)
        self.window.geometry(f"400x350+{x}+{y}")
    
    def _create_widgets(self):
        """Create the settings widgets."""
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Settings", font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Backup settings
        backup_frame = ttk.LabelFrame(main_frame, text="Backup Settings", padding="10")
        backup_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Checkbutton(backup_frame, text="Enable automatic backups", 
                       variable=self.auto_backup_var).pack(anchor=tk.W)
        
        # Security settings
        security_frame = ttk.LabelFrame(main_frame, text="Security Settings", padding="10")
        security_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Session timeout
        ttk.Label(security_frame, text="Session timeout (minutes):").pack(anchor=tk.W)
        timeout_frame = ttk.Frame(security_frame)
        timeout_frame.pack(fill=tk.X, pady=(5, 10))
        
        ttk.Scale(timeout_frame, from_=5, to=60, variable=self.session_timeout_var, 
                 orient=tk.HORIZONTAL).pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.timeout_label = ttk.Label(timeout_frame, text=f"{self.session_timeout_var.get()} min")
        self.timeout_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        self.session_timeout_var.trace('w', self._update_timeout_label)
        
        # Clipboard settings
        ttk.Label(security_frame, text="Auto-clear clipboard after (seconds):").pack(anchor=tk.W)
        clipboard_frame = ttk.Frame(security_frame)
        clipboard_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Scale(clipboard_frame, from_=10, to=300, variable=self.clipboard_clear_var, 
                 orient=tk.HORIZONTAL).pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.clipboard_label = ttk.Label(clipboard_frame, text=f"{self.clipboard_clear_var.get()} sec")
        self.clipboard_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        self.clipboard_clear_var.trace('w', self._update_clipboard_label)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Save Settings", command=self._on_save).pack(side=tk.RIGHT)
    
    def _update_timeout_label(self, *args):
        """Update session timeout label."""
        self.timeout_label.config(text=f"{self.session_timeout_var.get()} min")
    
    def _update_clipboard_label(self, *args):
        """Update clipboard clear label."""
        self.clipboard_label.config(text=f"{self.clipboard_clear_var.get()} sec")
    
    def _on_save(self):
        """Save settings."""
        try:
            self.password_manager.update_settings(
                auto_backup=self.auto_backup_var.get(),
                session_timeout=self.session_timeout_var.get() * 60,  # Convert to seconds
                clipboard_clear_time=self.clipboard_clear_var.get()
            )
            
            messagebox.showinfo("Success", "Settings saved successfully!")
            self.window.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def _on_cancel(self):
        """Cancel settings changes."""
        self.window.destroy() 