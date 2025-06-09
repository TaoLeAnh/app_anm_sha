"""
Dialog for viewing account passwords with master password verification.
"""

import os
import json
import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip
import base64
from cryptography.fernet import Fernet


class ViewPasswordDialog:
    """Dialog for viewing account passwords with master password verification."""
    
    def __init__(self, parent, password_manager, account_data):
        self.parent = parent
        self.password_manager = password_manager
        self.account_data = account_data
        self.window = None
        self.master_password_var = None
        self.password_display = None
        self.copy_button = None
        self.show_password_var = None
        self.decrypted_password = None
    
    def show(self):
        """Show the password verification dialog."""
        self.window = tk.Toplevel(self.parent)
        self.window.title("View Password")
        self.window.geometry("500x400")
        self.window.resizable(False, False)
        self.window.transient(self.parent)
        self.window.grab_set()
        
        # Center dialog
        self.window.update_idletasks()
        x = self.parent.winfo_x() + (self.parent.winfo_width() // 2) - (500 // 2)
        y = self.parent.winfo_y() + (self.parent.winfo_height() // 2) - (400 // 2)
        self.window.geometry(f"500x400+{x}+{y}")
    
        main_frame = ttk.Frame(self.window, padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Account info
        info_frame = ttk.LabelFrame(main_frame, text="Account Information", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(info_frame, text="Service:").pack(anchor=tk.W)
        ttk.Label(info_frame, text=self.account_data['service'], 
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Label(info_frame, text="Username:").pack(anchor=tk.W)
        ttk.Label(info_frame, text=self.account_data['username'], 
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        # Master password verification
        verify_frame = ttk.LabelFrame(main_frame, text="Master Password Verification", padding="10")
        verify_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(verify_frame, text="Enter master password to view:").pack(anchor=tk.W)
        
        self.master_password_var = tk.StringVar()
        password_entry = ttk.Entry(verify_frame, textvariable=self.master_password_var, show="*", width=40)
        password_entry.pack(fill=tk.X, pady=(5, 10))
        
        ttk.Button(verify_frame, text="View Password", 
                  command=self._verify_master_password).pack(anchor=tk.W)
        
        # Password display
        display_frame = ttk.LabelFrame(main_frame, text="Password", padding="10")
        display_frame.pack(fill=tk.X)
        
        # Create password display frame
        password_display_frame = ttk.Frame(display_frame)
        password_display_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create password display as Text widget instead of Entry
        self.password_display = tk.Text(password_display_frame, height=1, 
                                      font=('Arial', 11), wrap=tk.NONE)
        self.password_display.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.password_display.config(state='disabled')
        
        # Create show/hide checkbox
        self.show_password_var = tk.BooleanVar(value=False)
        show_check = ttk.Checkbutton(password_display_frame, text="Show Password", 
                                   variable=self.show_password_var,
                                   command=self._toggle_password_visibility)
        show_check.pack(side=tk.RIGHT)
        
        button_frame = ttk.Frame(display_frame)
        button_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.copy_button = ttk.Button(button_frame, text="Copy to Clipboard",
                                    command=self._copy_password, state=tk.DISABLED)
        self.copy_button.pack(side=tk.LEFT)
        
        # Close button
        ttk.Button(main_frame, text="Close", 
                  command=self._on_close).pack(fill=tk.X, pady=(20, 0))
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Handle Return key
        self.window.bind('<Return>', lambda e: self._verify_master_password())
        
        # Focus password entry
        password_entry.focus_set()
        
        self.window.wait_window()
    
    def _verify_master_password(self):
        """Verify master password and show the stored password if correct."""
        master_password = self.master_password_var.get()
        
        if not master_password:
            messagebox.showerror("Error", "Please enter the master password.")
            return
        
        try:
            # Debug: Print account data
            print("Account data:", self.account_data)
            
            # Load master password data
            master_file = os.path.join('data', 'master.json')
            with open(master_file, 'r') as f:
                master_data = json.load(f)
            
            # Debug: Print master data
            print("Master data:", master_data)
            
            # Verify master password
            is_valid = self.password_manager.encryption.verify_master_password(
                master_password,
                master_data['password_hash'],
                master_data['salt']
            )
            
            # Debug: Print master password verification result
            print("Master password verification:", is_valid)
            
            if is_valid:
                try:
                    # Get the encrypted password and salt
                    encrypted_password = self.account_data.get('encrypted_password')
                    salt = self.account_data.get('salt')
                    
                    # Debug: Print encryption data
                    print("Encrypted password:", encrypted_password)
                    print("Salt:", salt)
                    
                    if encrypted_password and salt:
                        # Decrypt the password using the encryption module
                        decrypted = self.password_manager.encryption.decrypt_password(
                            encrypted_password,
                            master_password,
                            salt
                        )
                        
                        # Debug: Print decrypted password
                        print("Decrypted password:", decrypted)
                        
                        # Store decrypted password
                        self.decrypted_password = decrypted
                        
                        # Update display with decrypted password
                        self.password_display.config(state='normal')
                        self.password_display.delete('1.0', tk.END)
                        
                        # Show as dots initially
                        dots = "●" * len(self.decrypted_password)
                        self.password_display.insert('1.0', dots)
                        
                        self.password_display.config(state='disabled')
                        
                        # Reset show password checkbox
                        self.show_password_var.set(False)
                        
                        # Enable copy button
                        self.copy_button.config(state=tk.NORMAL)
                        
                        # Force update the display
                        self.window.update_idletasks()
                    else:
                        messagebox.showerror("Error", "Password data is corrupted or missing.")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")
            else:
                messagebox.showerror("Error", "Incorrect master password!")
                self.master_password_var.set("")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify master password: {str(e)}")
    
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.decrypted_password:  # Only toggle if we have a decrypted password
            self.password_display.config(state='normal')
            self.password_display.delete('1.0', tk.END)
            
            if self.show_password_var.get():
                self.password_display.insert('1.0', self.decrypted_password)
            else:
                dots = "●" * len(self.decrypted_password)
                self.password_display.insert('1.0', dots)
                
            self.password_display.config(state='disabled')
            self.window.update_idletasks()
    
    def _copy_password(self):
        """Copy the decrypted password to clipboard."""
        if not self.decrypted_password:
            messagebox.showwarning(
                "Warning", 
                "Please verify the master password first before copying."
            )
            return
        
        try:
            pyperclip.copy(self.decrypted_password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")
    
    def _on_close(self):
        """Handle window close."""
        self.window.destroy() 