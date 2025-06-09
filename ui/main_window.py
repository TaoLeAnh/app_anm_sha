"""
Main application window for the password manager.
Contains the account list, search functionality, categories, and main UI features.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyperclip
from typing import List, Dict, Optional
from ui.dialogs import AddAccountDialog, PasswordGeneratorDialog, SettingsDialog
from .view_password_dialog import ViewPasswordDialog


class MainWindow:
    """Main application window for the password manager."""
    
    def __init__(self, password_manager):
        self.password_manager = password_manager
        self.window = None
        self.current_accounts = []
        self.selected_category = "All"
        
        # Variables - will be initialized in show()
        self.search_var = None
        self.sort_var = None
    
    def show(self):
        """Show the main application window."""
        self.window = tk.Tk()
        self.window.title("Password Manager")
        self.window.geometry("1000x700")
        self.window.minsize(800, 600)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Initialize tkinter variables after window is created
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self._on_search_change)
        self.sort_var = tk.StringVar(value="Service")
        
        # Center the window
        self._center_window()
        
        self._create_widgets()
        self._refresh_accounts()
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Configure keyboard shortcuts
        self._setup_keyboard_shortcuts()
        
        self.window.mainloop()
    
    def _center_window(self):
        """Center the window on screen."""
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (1000 // 2)
        y = (self.window.winfo_screenheight() // 2) - (700 // 2)
        self.window.geometry(f"1000x700+{x}+{y}")
    
    def _create_widgets(self):
        """Create the main window widgets."""
        # Create main container
        main_container = ttk.Frame(self.window)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create header
        self._create_header(main_container)
        
        # Create main content area
        content_frame = ttk.Frame(main_container)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create sidebar and main area
        self._create_sidebar(content_frame)
        self._create_main_area(content_frame)
        
        # Create footer
        self._create_footer(main_container)
    
    def _create_header(self, parent):
        """Create the header with title and controls."""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title_label = ttk.Label(header_frame, text="Personal Password Manager", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(side=tk.LEFT)
        
        # Header buttons
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side=tk.RIGHT)
        
        ttk.Button(button_frame, text="Settings", command=self._show_settings).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Export", command=self._export_data).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Import", command=self._import_data).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Generate Password", 
                  command=self._generate_password).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Logout", command=self._logout).pack(side=tk.RIGHT, padx=(5, 0))
    
    def _create_sidebar(self, parent):
        """Create the sidebar with categories and controls."""
        sidebar_frame = ttk.Frame(parent, width=250)
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        sidebar_frame.pack_propagate(False)
        
        # Add Account button
        ttk.Button(sidebar_frame, text="+ Add New Account", 
                  command=self._add_account, style="Accent.TButton").pack(fill=tk.X, pady=(0, 15))
        
        # Search
        search_frame = ttk.LabelFrame(sidebar_frame, text="Search", padding="10")
        search_frame.pack(fill=tk.X, pady=(0, 15))
        
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, font=('Arial', 10))
        search_entry.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(search_frame, text="Clear", command=self._clear_search).pack(fill=tk.X)
        
        # Categories
        categories_frame = ttk.LabelFrame(sidebar_frame, text="Categories", padding="10")
        categories_frame.pack(fill=tk.BOTH, expand=True)
        
        # Categories listbox
        self.categories_listbox = tk.Listbox(categories_frame, font=('Arial', 10), 
                                           selectmode=tk.SINGLE, height=12)
        self.categories_listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.categories_listbox.bind('<<ListboxSelect>>', self._on_category_select)
        
        # Add category button
        ttk.Button(categories_frame, text="Add Category", 
                  command=self._add_category).pack(fill=tk.X)
        
        self._populate_categories()
    
    def _create_main_area(self, parent):
        """Create the main area with account list."""
        main_frame = ttk.Frame(parent)
        main_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Account list header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.accounts_count_label = ttk.Label(header_frame, text="All Accounts (0)", 
                                            font=('Arial', 12, 'bold'))
        self.accounts_count_label.pack(side=tk.LEFT)
        
        # Sort options
        sort_frame = ttk.Frame(header_frame)
        sort_frame.pack(side=tk.RIGHT)
        
        ttk.Label(sort_frame, text="Sort by:").pack(side=tk.LEFT, padx=(0, 5))
        sort_combo = ttk.Combobox(sort_frame, values=["Service", "Username", "Category", "Date"], 
                                 width=10, state="readonly", textvariable=self.sort_var)
        sort_combo.pack(side=tk.LEFT)
        sort_combo.bind('<<ComboboxSelected>>', self._on_sort_change)
        
        # Account list
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview for accounts
        columns = ("Service", "Username", "Category", "Modified")
        self.accounts_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        # Define column headings and widths
        self.accounts_tree.heading("Service", text="Service")
        self.accounts_tree.heading("Username", text="Username")
        self.accounts_tree.heading("Category", text="Category")
        self.accounts_tree.heading("Modified", text="Last Modified")
        
        self.accounts_tree.column("Service", width=200, minwidth=150)
        self.accounts_tree.column("Username", width=200, minwidth=150)
        self.accounts_tree.column("Category", width=120, minwidth=100)
        self.accounts_tree.column("Modified", width=120, minwidth=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.accounts_tree.yview)
        self.accounts_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.accounts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind events
        self.accounts_tree.bind('<Double-1>', self._on_account_double_click)
        self.accounts_tree.bind('<Button-3>', self._on_account_right_click)
        
        # Context menu
        self._create_context_menu()
        
        # Action buttons
        self._create_action_buttons(main_frame)
    
    def _create_context_menu(self):
        """Create right-click context menu for accounts."""
        self.context_menu = tk.Menu(self.window, tearoff=0)
        self.context_menu.add_command(label="View Password", command=self._view_password)
        self.context_menu.add_command(label="Copy Username", command=self._copy_username)
        self.context_menu.add_command(label="Copy Password", command=self._copy_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Edit Account", command=self._edit_account)
        self.context_menu.add_command(label="Delete Account", command=self._delete_account)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Open URL", command=self._open_url)
    
    def _create_action_buttons(self, parent):
        """Create action buttons below the account list."""
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(button_frame, text="View Password", 
                  command=self._view_password).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Copy Username", 
                  command=self._copy_username).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Copy Password", 
                  command=self._copy_password).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Edit", 
                  command=self._edit_account).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Delete", 
                  command=self._delete_account).pack(side=tk.LEFT, padx=(0, 5))
    
    def _create_footer(self, parent):
        """Create the footer with status information."""
        footer_frame = ttk.Frame(parent)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Status information
        stats = self.password_manager.get_vault_stats()
        
        self.status_label = ttk.Label(footer_frame, 
                                    text=f"Total Accounts: {stats['total_accounts']} | "
                                         f"Vault Size: {stats['vault_file_size']} bytes")
        self.status_label.pack(side=tk.LEFT)
        
        # Version info
        version_label = ttk.Label(footer_frame, text="v1.0.0", font=('Arial', 8))
        version_label.pack(side=tk.RIGHT)
    
    def _setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts."""
        self.window.bind('<Control-n>', lambda e: self._add_account())
        self.window.bind('<Control-f>', lambda e: self.search_var.set(""))
        self.window.bind('<Delete>', lambda e: self._delete_account())
        self.window.bind('<F2>', lambda e: self._edit_account())
        self.window.bind('<Control-g>', lambda e: self._generate_password())
        self.window.bind('<Control-q>', lambda e: self._logout())
    
    def _populate_categories(self):
        """Populate the categories listbox."""
        self.categories_listbox.delete(0, tk.END)
        
        # Add "All" category
        self.categories_listbox.insert(tk.END, "All")
        
        # Add other categories
        categories = self.password_manager.get_categories()
        for category in categories:
            self.categories_listbox.insert(tk.END, category)
        
        # Select "All" by default
        self.categories_listbox.selection_set(0)
    
    def _refresh_accounts(self):
        """Refresh the accounts list."""
        try:
            # Clear existing items
            for item in self.accounts_tree.get_children():
                self.accounts_tree.delete(item)
            
            # Get accounts based on current filter
            if self.selected_category == "All":
                accounts = self.password_manager.get_all_accounts()
            else:
                accounts = self.password_manager.get_accounts_by_category(self.selected_category)
            
            # Apply search filter
            search_query = self.search_var.get().strip()
            if search_query:
                accounts = self.password_manager.search_accounts(search_query)
            
            # Sort accounts based on selected option
            sort_by = self.sort_var.get()
            if sort_by == "Service (A-Z)":
                accounts.sort(key=lambda x: x['service'].lower())
            elif sort_by == "Service (Z-A)":
                accounts.sort(key=lambda x: x['service'].lower(), reverse=True)
            elif sort_by == "Username (A-Z)":
                accounts.sort(key=lambda x: x['username'].lower())
            elif sort_by == "Username (Z-A)":
                accounts.sort(key=lambda x: x['username'].lower(), reverse=True)
            elif sort_by == "Recently Modified":
                accounts.sort(key=lambda x: x['modified_date'], reverse=True)
            elif sort_by == "Recently Created":
                accounts.sort(key=lambda x: x['created_date'], reverse=True)
            
            # Store current accounts for reference
            self.current_accounts = []
            
            # Update tree view
            for account in accounts:
                # Get full account data from password manager
                account_id = account.get('id')
                if account_id:
                    try:
                        full_account = self.password_manager.get_account(account_id)
                        self.current_accounts.append(full_account)
                    except Exception:
                        self.current_accounts.append(account)
                else:
                    self.current_accounts.append(account)
                
                # Add to tree view
                self.accounts_tree.insert(
                    "",
                    tk.END,
                    values=(
                        account['service'],
                        account['username'],
                        account.get('url', ''),
                        account['category']
                    )
                )
            
            # Update status
            self._update_status()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh accounts: {str(e)}")
            self.current_accounts = []
    
    def _update_status(self):
        """Update the status bar."""
        stats = self.password_manager.get_vault_stats()
        self.status_label.config(
            text=f"Total Accounts: {stats['total_accounts']} | "
                 f"Vault Size: {stats['vault_file_size']} bytes"
        )
    
    def _get_selected_account(self) -> Optional[Dict]:
        """Get the currently selected account."""
        selection = self.accounts_tree.selection()
        if not selection:
            return None
        
        item = selection[0]
        values = self.accounts_tree.item(item, 'values')
        
        # Find account by service and username
        for account in self.current_accounts:
            if (account['service'] == values[0] and 
                account['username'] == values[1]):
                # Check if we have complete account data
                if ('encrypted_password' in account and 
                    'salt' in account and 
                    'password_hash' in account):
                    return account
                
                # Get full account data from password manager
                account_id = account.get('id')
                if account_id:
                    try:
                        return self.password_manager.get_account(account_id)
                    except Exception:
                        return account
                return account
        
        return None
    
    def _on_search_change(self, *args):
        """Handle search text change."""
        self._refresh_accounts()
    
    def _on_category_select(self, event):
        """Handle category selection."""
        selection = self.categories_listbox.curselection()
        if selection:
            self.selected_category = self.categories_listbox.get(selection[0])
            self._refresh_accounts()
    
    def _on_account_double_click(self, event):
        """Handle double-click on account."""
        self._view_password()
    
    def _on_account_right_click(self, event):
        """Handle right-click on account."""
        # Select the item under cursor
        item = self.accounts_tree.identify_row(event.y)
        if item:
            self.accounts_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def _clear_search(self):
        """Clear search field."""
        self.search_var.set("")
    
    def _add_account(self):
        """Show add account dialog."""
        dialog = AddAccountDialog(self.window, self.password_manager, 
                                self.password_manager.get_categories())
        result = dialog.show()
        
        if result:
            try:
                # Add the account
                self.password_manager.add_account(
                    service=result['service'],
                    username=result['username'],
                    password=result['password'],
                    url=result['url'],
                    notes=result['notes'],
                    category=result['category']
                )
                
                # Refresh data and UI immediately
                self.password_manager.reload_vault()
                self._refresh_accounts()
                self._populate_categories()
                
                # Show success message
                messagebox.showinfo("Success", "Account added successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add account: {str(e)}")
    
    def _view_password(self):
        """Show password view dialog."""
        account = self._get_selected_account()
        if not account:
            messagebox.showwarning("Warning", "Please select an account first.")
            return
        
        dialog = ViewPasswordDialog(self.window, self.password_manager, account)
        dialog.show()
    
    def _copy_username(self):
        """Copy username to clipboard."""
        account = self._get_selected_account()
        if not account:
            messagebox.showwarning("Warning", "Please select an account first.")
            return
        
        try:
            pyperclip.copy(account['username'])
            messagebox.showinfo("Copied", "Username copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy username: {str(e)}")
    
    def _copy_password(self):
        """Copy password to clipboard."""
        account = self._get_selected_account()
        if not account:
            messagebox.showwarning("Warning", "Please select an account first.")
            return
        
        try:
            self.password_manager.copy_to_clipboard(account['password'])
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy password: {str(e)}")
    
    def _edit_account(self):
        """Show edit account dialog."""
        account = self._get_selected_account()
        if not account:
            messagebox.showwarning("Warning", "Please select an account first.")
            return
        
        dialog = AddAccountDialog(self.window, self.password_manager, 
                                self.password_manager.get_categories(), account)
        result = dialog.show()
        
        if result:
            try:
                self.password_manager.update_account(
                    account_id=account['id'],
                    service=result['service'],
                    username=result['username'],
                    password=result['password'],
                    url=result['url'],
                    notes=result['notes'],
                    category=result['category']
                )
                # Reload data and update UI
                self.password_manager.reload_vault()
                self.window.after(100, self._refresh_accounts)  # Schedule refresh after a short delay
                messagebox.showinfo("Success", "Account updated successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update account: {str(e)}")
    
    def _delete_account(self):
        """Delete the selected account."""
        account = self._get_selected_account()
        if not account:
            messagebox.showwarning("Warning", "Please select an account first.")
            return
        
        result = messagebox.askyesno("Confirm Delete", 
                                   f"Are you sure you want to delete the account for "
                                   f"{account['service']}?\n\nThis action cannot be undone.")
        if result:
            try:
                self.password_manager.delete_account(account['id'])
                # Reload data and update UI
                self.password_manager.reload_vault()
                self.window.after(100, self._refresh_accounts)  # Schedule refresh after a short delay
                messagebox.showinfo("Success", "Account deleted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete account: {str(e)}")
    
    def _open_url(self):
        """Open the account URL in browser."""
        account = self._get_selected_account()
        if not account:
            messagebox.showwarning("Warning", "Please select an account first.")
            return
        
        url = account.get('url', '').strip()
        if not url:
            messagebox.showwarning("Warning", "No URL specified for this account.")
            return
        
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open URL: {str(e)}")
    
    def _add_category(self):
        """Add a new category."""
        dialog = tk.Toplevel(self.window)
        dialog.title("Add Category")
        dialog.geometry("300x150")
        dialog.resizable(False, False)
        dialog.transient(self.window)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.window.winfo_x() + (self.window.winfo_width() // 2) - (300 // 2)
        y = self.window.winfo_y() + (self.window.winfo_height() // 2) - (150 // 2)
        dialog.geometry(f"300x150+{x}+{y}")
        
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Category Name:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        category_var = tk.StringVar()
        entry = ttk.Entry(main_frame, textvariable=category_var, font=('Arial', 11))
        entry.pack(fill=tk.X, pady=(5, 20))
        entry.focus_set()
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def add_category():
            category = category_var.get().strip()
            if category:
                try:
                    self.password_manager.add_category(category)
                    self._populate_categories()
                    dialog.destroy()
                    messagebox.showinfo("Success", "Category added successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to add category: {str(e)}")
            else:
                messagebox.showwarning("Warning", "Please enter a category name.")
        
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Add", command=add_category).pack(side=tk.RIGHT)
        
        dialog.bind('<Return>', lambda e: add_category())
    
    def _generate_password(self):
        """Show password generator dialog."""
        dialog = PasswordGeneratorDialog(self.window, self.password_manager)
        password = dialog.show()
        
        if password:
            try:
                pyperclip.copy(password)
                messagebox.showinfo("Generated", 
                                  f"Password generated and copied to clipboard!\n\n"
                                  f"Length: {len(password)} characters")
            except Exception as e:
                messagebox.showwarning("Generated", 
                                     f"Password generated: {password}\n\n"
                                     f"Could not copy to clipboard: {str(e)}")
    
    def _show_settings(self):
        """Show settings dialog."""
        dialog = SettingsDialog(self.window, self.password_manager)
        dialog.show()
    
    def _import_data(self):
        """Import data from file."""
        file_path = filedialog.askopenfilename(
            title="Import Data",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                count = self.password_manager.import_data(file_path)
                self._refresh_accounts()
                self._populate_categories()
                messagebox.showinfo("Success", f"Successfully imported {count} accounts!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import data: {str(e)}")
    
    def _export_data(self):
        """Export data to file."""
        file_path = filedialog.asksaveasfilename(
            title="Export Data",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            include_passwords = messagebox.askyesno("Export Passwords", 
                                                  "Do you want to include passwords in the export?\n\n"
                                                  "Warning: This will export passwords in plain text.")
            try:
                self.password_manager.export_data(file_path, include_passwords)
                messagebox.showinfo("Success", f"Data exported successfully to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def _logout(self):
        """Logout and close the application."""
        result = messagebox.askyesno("Logout", "Are you sure you want to logout?")
        if result:
            self._on_close()
    
    def _on_close(self):
        """Handle window close."""
        try:
            # Save any pending changes
            self.password_manager.save_vault()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save data: {str(e)}")
        
        self.window.destroy()
    
    def _on_sort_change(self, event):
        """Handle sort option change."""
        self._refresh_accounts() 