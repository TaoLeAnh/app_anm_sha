"""
Master password setup module.
Handles the initial creation and validation of the master password.
"""

import os
import json
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from encryption import PasswordEncryption


class MasterPasswordSetup:
    """Handles the initial master password setup process."""
    
    def __init__(self):
        self.encryption = PasswordEncryption()
        self.master_file = os.path.join('data', 'master.json')
        self.window = None
        self.password_var = None
        self.confirm_var = None
        self.show_password_var = None
        self.strength_label = None
        self.strength_progress = None
        self.feedback_text = None
        self.master_password = None
    
    def needs_setup(self) -> bool:
        """Check if master password setup is required."""
        return not os.path.exists(self.master_file)
    
    def show_setup_window(self) -> str:
        """
        Show the master password setup window.
        
        Returns:
            The master password if setup is successful, None if cancelled
        """
        self.window = tk.Tk()
        self.window.title("Password Manager - Master Password Setup")
        self.window.geometry("500x600")
        self.window.resizable(False, False)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Center the window
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.window.winfo_screenheight() // 2) - (600 // 2)
        self.window.geometry(f"500x600+{x}+{y}")
        
        self._create_setup_widgets()
        
        # Make window modal
        self.window.transient()
        self.window.grab_set()
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self._on_cancel)
        
        self.window.mainloop()
        
        return self.master_password
    
    def _create_setup_widgets(self):
        """Create the setup window widgets."""
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Set Up Master Password", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Description
        desc_text = ("Your master password protects all your stored passwords. "
                    "Make it strong and memorable - you'll need it every time you use the app.")
        desc_label = ttk.Label(main_frame, text=desc_text, wraplength=450, justify=tk.LEFT)
        desc_label.pack(pady=(0, 20))
        
        # Password requirements
        req_frame = ttk.LabelFrame(main_frame, text="Password Requirements", padding="10")
        req_frame.pack(fill=tk.X, pady=(0, 20))
        
        requirements = [
            "• At least 8 characters long",
            "• Include uppercase and lowercase letters",
            "• Include at least one number",
            "• Include at least one symbol (!@#$%^&*, etc.)"
        ]
        
        for req in requirements:
            req_label = ttk.Label(req_frame, text=req, font=('Arial', 9))
            req_label.pack(anchor=tk.W)
        
        # Password input
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(password_frame, text="Master Password:").pack(anchor=tk.W)
        
        password_input_frame = ttk.Frame(password_frame)
        password_input_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.password_var = tk.StringVar()
        self.password_var.trace('w', self._on_password_change)
        
        self.password_entry = ttk.Entry(password_input_frame, textvariable=self.password_var, 
                                       show="*", font=('Arial', 11), width=30)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_password_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(password_input_frame, text="Show", 
                                   variable=self.show_password_var,
                                   command=self._toggle_password_visibility)
        show_check.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Password strength indicator
        strength_frame = ttk.Frame(main_frame)
        strength_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(strength_frame, text="Password Strength:").pack(anchor=tk.W)
        
        self.strength_progress = ttk.Progressbar(strength_frame, length=300, mode='determinate')
        self.strength_progress.pack(fill=tk.X, pady=(5, 0))
        
        self.strength_label = ttk.Label(strength_frame, text="", font=('Arial', 9, 'bold'))
        self.strength_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Feedback text
        self.feedback_text = tk.Text(main_frame, height=4, width=50, wrap=tk.WORD, 
                                   font=('Arial', 9), state=tk.DISABLED)
        self.feedback_text.pack(fill=tk.X, pady=(0, 10))
        
        # Confirm password
        confirm_frame = ttk.Frame(main_frame)
        confirm_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(confirm_frame, text="Confirm Master Password:").pack(anchor=tk.W)
        
        self.confirm_var = tk.StringVar()
        self.confirm_entry = ttk.Entry(confirm_frame, textvariable=self.confirm_var, 
                                     show="*", font=('Arial', 11))
        self.confirm_entry.pack(fill=tk.X, pady=(5, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Create Master Password", 
                  command=self._on_create).pack(side=tk.RIGHT)
        
        # Focus on password entry
        self.password_entry.focus_set()
        
        # Bind Enter key
        self.window.bind('<Return>', lambda e: self._on_create())
    
    def _on_password_change(self, *args):
        """Handle password change to update strength indicator."""
        password = self.password_var.get()
        
        if not password:
            self.strength_progress['value'] = 0
            self.strength_label.config(text="")
            self._update_feedback([])
            return
        
        strength_result = self.encryption.check_password_strength(password)
        
        # Update progress bar
        self.strength_progress['value'] = strength_result['score']
        
        # Update strength label with color
        strength_text = strength_result['strength']
        self.strength_label.config(text=strength_text)
        
        # Color coding
        if strength_result['score'] < 30:
            color = 'red'
        elif strength_result['score'] < 50:
            color = 'orange'
        elif strength_result['score'] < 70:
            color = 'gold'
        elif strength_result['score'] < 90:
            color = 'blue'
        else:
            color = 'green'
        
        self.strength_label.config(foreground=color)
        
        # Update feedback
        self._update_feedback(strength_result['feedback'])
    
    def _update_feedback(self, feedback_list):
        """Update the feedback text widget."""
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        
        if feedback_list:
            feedback_text = "Suggestions to improve password strength:\n"
            for feedback in feedback_list:
                feedback_text += f"• {feedback}\n"
            self.feedback_text.insert(1.0, feedback_text)
        
        self.feedback_text.config(state=tk.DISABLED)
    
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.config(show="")
            self.confirm_entry.config(show="")
        else:
            self.password_entry.config(show="*")
            self.confirm_entry.config(show="*")
    
    def _validate_passwords(self) -> bool:
        """Validate the entered passwords."""
        password = self.password_var.get()
        confirm = self.confirm_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a master password.")
            return False
        
        if not confirm:
            messagebox.showerror("Error", "Please confirm your master password.")
            return False
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return False
        
        # Check password strength
        strength = self.encryption.check_password_strength(password)
        if strength['score'] < 50:
            result = messagebox.askyesno(
                "Warning",
                "The password you entered is weak. This could make your stored "
                "passwords vulnerable.\n\nAre you sure you want to use this password?"
            )
            return result
        
        return True
    
    def _on_create(self):
        """Handle master password creation."""
        if not self._validate_passwords():
            return
        
        try:
            # Create data directory if it doesn't exist
            os.makedirs('data', exist_ok=True)
            
            # Hash the master password
            password = self.password_var.get()
            master_data = self.encryption.hash_master_password(password)
            
            # Add creation date
            master_data['created_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Save to file
            with open(self.master_file, 'w') as f:
                json.dump(master_data, f, indent=2)
            
            # Store password for return
            self.master_password = password
            
            messagebox.showinfo(
                "Success", 
                "Master password created successfully!\n\n"
                "Please remember this password - it cannot be recovered if lost."
            )
            
            # Close window
            if self.window:
                self.window.destroy()
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create master password: {str(e)}")
    
    def _on_cancel(self):
        """Handle setup cancellation."""
        result = messagebox.askyesno("Cancel Setup", 
                                   "Are you sure you want to cancel? "
                                   "You won't be able to use the password manager without a master password.")
        if result:
            self.window.destroy()


def main():
    """Main function for testing the setup process."""
    setup = MasterPasswordSetup()
    
    if setup.needs_setup():
        password = setup.show_setup_window()
        if password:
            print("Master password setup completed successfully!")
        else:
            print("Setup cancelled.")
    else:
        print("Master password already exists.")


if __name__ == "__main__":
    main() 