"""
Login window for the password manager application.
Handles user authentication with security features like attempt limiting and session timeout.
"""

import os
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox
from threading import Timer
from encryption import PasswordEncryption


class LoginWindow:
    """Login window with secure authentication features."""
    
    def __init__(self):
        self.encryption = PasswordEncryption()
        self.master_file = os.path.join('data', 'master.json')
        self.window = None
        self.password_var = None
        self.show_password_var = None
        self.login_successful = False
        self.master_password = None
        
        # Security features
        self.max_attempts = 3
        self.current_attempts = 0
        self.lockout_time = 30  # seconds
        self.locked_until = 0
        self.session_timeout = 1800  # 30 minutes in seconds
        self.last_activity = time.time()
        self.activity_timer = None
    
    def show_login_window(self) -> tuple:
        """
        Show the login window.
        
        Returns:
            Tuple of (success: bool, master_password: str)
        """
        if not os.path.exists(self.master_file):
            messagebox.showerror("Error", "Master password not found. Please set up the application first.")
            return False, None
        
        self.window = tk.Tk()
        self.window.title("Password Manager - Login")
        self.window.geometry("400x300")
        self.window.resizable(False, False)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Center the window
        self._center_window()
        
        self._create_login_widgets()
        
        # Make window modal
        self.window.transient()
        self.window.grab_set()
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self._on_cancel)
        
        # Start activity monitoring
        self._start_activity_monitoring()
        
        self.window.mainloop()
        
        return self.login_successful, self.master_password
    
    def _center_window(self):
        """Center the window on screen."""
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.window.winfo_screenheight() // 2) - (300 // 2)
        self.window.geometry(f"400x300+{x}+{y}")
    
    def _create_login_widgets(self):
        """Create the login window widgets."""
        main_frame = ttk.Frame(self.window, padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Password Manager", 
                               font=('Arial', 18, 'bold'))
        title_label.pack(pady=(0, 10))
        
        subtitle_label = ttk.Label(main_frame, text="Enter your master password", 
                                 font=('Arial', 11))
        subtitle_label.pack(pady=(0, 30))
        
        # Password input frame
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(password_frame, text="Master Password:", font=('Arial', 11)).pack(anchor=tk.W, pady=(0, 5))
        
        # Password entry with show/hide toggle
        password_input_frame = ttk.Frame(password_frame)
        password_input_frame.pack(fill=tk.X)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_input_frame, textvariable=self.password_var, 
                                       show="*", font=('Arial', 12), width=25)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_password_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(password_input_frame, text="Show", 
                                   variable=self.show_password_var,
                                   command=self._toggle_password_visibility)
        show_check.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Attempt counter and lockout message
        self.status_label = ttk.Label(main_frame, text="", font=('Arial', 9), foreground='red')
        self.status_label.pack(pady=(0, 10))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.login_button = ttk.Button(button_frame, text="Login", command=self._on_login)
        self.login_button.pack(side=tk.RIGHT, padx=(10, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)
        
        # Focus on password entry
        self.password_entry.focus_set()
        
        # Bind Enter key
        self.window.bind('<Return>', lambda e: self._on_login())
        
        # Check if currently locked out
        self._check_lockout_status()
    
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def _check_lockout_status(self):
        """Check if the user is currently locked out."""
        current_time = time.time()
        if current_time < self.locked_until:
            remaining_time = int(self.locked_until - current_time)
            self.status_label.config(text=f"Too many failed attempts. Try again in {remaining_time} seconds.")
            self.login_button.config(state='disabled')
            self.password_entry.config(state='disabled')
            
            # Schedule to re-enable after lockout period
            self.window.after(1000, self._check_lockout_status)
        else:
            self.status_label.config(text="")
            self.login_button.config(state='normal')
            self.password_entry.config(state='normal')
            if self.current_attempts > 0:
                attempts_left = self.max_attempts - self.current_attempts
                if attempts_left > 0:
                    self.status_label.config(text=f"Attempts remaining: {attempts_left}")
    
    def _load_master_data(self) -> dict:
        """Load master password data from file."""
        try:
            with open(self.master_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load master password data: {str(e)}")
            return None
    
    def _on_login(self):
        """Handle login attempt."""
        # Check if locked out
        if time.time() < self.locked_until:
            return
        
        password = self.password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter your master password.")
            return
        
        # Load master password data
        master_data = self._load_master_data()
        if not master_data:
            return
        
        # Verify password
        is_valid = self.encryption.verify_master_password(
            password, 
            master_data['password_hash'], 
            master_data['salt']
        )
        
        if is_valid:
            # Successful login
            self.login_successful = True
            self.master_password = password
            self.current_attempts = 0
            self._reset_activity_timer()
            self.window.destroy()
        else:
            # Failed login
            self.current_attempts += 1
            attempts_left = self.max_attempts - self.current_attempts
            
            if attempts_left > 0:
                messagebox.showerror("Error", f"Incorrect password. {attempts_left} attempts remaining.")
                self.status_label.config(text=f"Attempts remaining: {attempts_left}")
                self.password_var.set("")  # Clear password field
                self.password_entry.focus_set()
            else:
                # Lock out user
                self.locked_until = time.time() + self.lockout_time
                self.status_label.config(text=f"Too many failed attempts. Locked out for {self.lockout_time} seconds.")
                self.login_button.config(state='disabled')
                self.password_entry.config(state='disabled')
                self.password_var.set("")
                
                messagebox.showerror("Account Locked", 
                                   f"Too many failed login attempts. "
                                   f"Please wait {self.lockout_time} seconds before trying again.")
                
                # Reset attempts counter after lockout
                self.window.after(self.lockout_time * 1000, self._reset_attempts)
    
    def _reset_attempts(self):
        """Reset login attempts counter after lockout period."""
        self.current_attempts = 0
        self._check_lockout_status()
    
    def _start_activity_monitoring(self):
        """Start monitoring user activity for session timeout."""
        self.last_activity = time.time()
        self._reset_activity_timer()
        
        # Bind activity events
        self.window.bind('<Key>', self._on_activity)
        self.window.bind('<Button>', self._on_activity)
        self.window.bind('<Motion>', self._on_activity)
    
    def _on_activity(self, event=None):
        """Handle user activity."""
        self.last_activity = time.time()
        self._reset_activity_timer()
    
    def _reset_activity_timer(self):
        """Reset the session timeout timer."""
        if self.activity_timer:
            self.activity_timer.cancel()
        
        self.activity_timer = Timer(self.session_timeout, self._on_session_timeout)
        self.activity_timer.start()
    
    def _on_session_timeout(self):
        """Handle session timeout."""
        if self.window and self.window.winfo_exists():
            messagebox.showwarning("Session Timeout", 
                                 "Your session has timed out for security reasons. "
                                 "Please log in again.")
            self._on_cancel()
    
    def _on_cancel(self):
        """Handle login cancellation."""
        if self.activity_timer:
            self.activity_timer.cancel()
        self.window.destroy()
    
    def get_session_timeout(self) -> int:
        """Get the session timeout value."""
        return self.session_timeout
    
    def set_session_timeout(self, timeout: int):
        """Set the session timeout value."""
        self.session_timeout = max(300, min(3600, timeout))  # Between 5 minutes and 1 hour


def main():
    """Main function for testing the login window."""
    login = LoginWindow()
    success, password = login.show_login_window()
    
    if success:
        print("Login successful!")
    else:
        print("Login cancelled or failed.")


if __name__ == "__main__":
    main() 