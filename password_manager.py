"""
Core password manager logic.
Handles account data storage, hashing, search, and backup functionality.
"""

import os
import json
import uuid
import shutil
import pyperclip
from datetime import datetime
from typing import List, Dict, Optional
from encryption import PasswordEncryption
import base64
from cryptography.fernet import Fernet


class PasswordManager:
    """Core password manager for handling account data and operations."""
    
    def __init__(self, master_password: str):
        self.master_password = master_password
        self.encryption = PasswordEncryption()
        self.vault_file = os.path.join('data', 'vault.json')
        self.backup_dir = os.path.join('data', 'backups')
        self.accounts = {}
        self.categories = [
            "Social Media", "Email", "Banking", "Work", 
            "Personal", "Shopping", "Entertainment", "Other"
        ]
        self.settings = {
            "auto_backup": True,
            "session_timeout": 1800,
            "clipboard_clear_time": 30
        }
        self._load_vault()
    
    def _load_vault(self):
        """Load the password vault."""
        if not os.path.exists(self.vault_file):
            self._create_empty_vault()
            return
        
        try:
            # Try to read the file
            try:
                with open(self.vault_file, 'r') as f:
                    vault_data = json.load(f)
            except json.JSONDecodeError:
                # If file is corrupted, try to restore from backup
                self._restore_from_latest_backup()
                with open(self.vault_file, 'r') as f:
                    vault_data = json.load(f)
            
            self.settings.update(vault_data.get('settings', {}))
            self.categories = vault_data.get('categories', self.categories)
            
            # Load accounts
            self.accounts = vault_data.get('accounts', {})
                    
        except Exception as e:
            raise Exception(f"Failed to load vault: {str(e)}")
    
    def _create_empty_vault(self):
        """Create an empty vault file."""
        os.makedirs('data', exist_ok=True)
        
        vault_data = {
            "version": "1.0",
            "accounts": {},
            "categories": self.categories,
            "settings": self.settings
        }
        
        with open(self.vault_file, 'w') as f:
            json.dump(vault_data, f, indent=2)
    
    def save_vault(self):
        """Save the password vault."""
        try:
            # Create backup if auto-backup is enabled
            if self.settings.get('auto_backup', True) and os.path.exists(self.vault_file):
                self._create_backup()
            
            # Create vault data
            vault_data = {
                "version": "1.0",
                "accounts": self.accounts,
                "categories": self.categories,
                "settings": self.settings
            }
            
            # Create temp file for atomic write
            temp_file = self.vault_file + '.tmp'
            
            # Write to temp file first
            with open(temp_file, 'w') as f:
                json.dump(vault_data, f, indent=2)
            
            # Verify the temp file was written correctly
            try:
                with open(temp_file, 'r') as f:
                    test_data = json.load(f)
                if not test_data:
                    raise Exception("Failed to verify temp file")
            except Exception as e:
                os.remove(temp_file)
                raise Exception(f"Failed to verify temp file: {str(e)}")
            
            # Rename temp file to actual file (atomic operation)
            os.replace(temp_file, self.vault_file)
                
        except Exception as e:
            raise Exception(f"Failed to save vault: {str(e)}")
    
    def add_account(self, service: str, username: str, password: str, 
                   url: str = "", notes: str = "", category: str = "Other") -> str:
        """
        Add a new account to the vault.
        
        Args:
            service: Service name (required)
            username: Username or email (required)
            password: Password (required)
            url: Website URL (optional)
            notes: Additional notes (optional)
            category: Account category (optional)
            
        Returns:
            Account ID of the created account
        """
        if not service or not username or not password:
            raise ValueError("Service, username, and password are required")
        
        if category not in self.categories:
            category = "Other"
        
        # Hash and encrypt the password
        password_data = self.encryption.hash_and_encrypt_password(password, self.master_password)
        
        account_id = str(uuid.uuid4())
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        account_data = {
            'service': service,
            'username': username,
            'password_hash': password_data['password_hash'],
            'encrypted_password': password_data['encrypted_password'],
            'salt': password_data['salt'],
            'url': url,
            'notes': notes,
            'category': category,
            'created_date': current_time,
            'modified_date': current_time
        }
        
        self.accounts[account_id] = account_data
        self.save_vault()
        
        return account_id
    
    def verify_and_get_password(self, account_id: str, password: str) -> tuple[bool, str]:
        """
        Verify if a password matches and return the stored password.
        
        Args:
            account_id: The account ID
            password: The password to verify
            
        Returns:
            Tuple of (is_valid, decrypted_password)
        """
        account = self.accounts.get(account_id)
        if not account:
            return False, ""
        
        return self.encryption.verify_and_decrypt_password(
            password,
            account['password_hash'],
            account['encrypted_password'],
            account['salt'],
            self.master_password
        )
    
    def update_account(self, account_id: str, service: str = None, username: str = None,
                      password: str = None, url: str = None, notes: str = None,
                      category: str = None) -> bool:
        """
        Update an existing account.
        
        Args:
            account_id: The account ID to update
            service: New service name (optional)
            username: New username (optional)
            password: New password (optional)
            url: New URL (optional)
            notes: New notes (optional)
            category: New category (optional)
            
        Returns:
            True if successful, False otherwise
        """
        if account_id not in self.accounts:
            return False
        
        account = self.accounts[account_id]
        
        if service is not None:
            account['service'] = service
        if username is not None:
            account['username'] = username
        if password is not None:
            # Hash and encrypt the new password
            password_data = self.encryption.hash_and_encrypt_password(password, self.master_password)
            account['password_hash'] = password_data['password_hash']
            account['encrypted_password'] = password_data['encrypted_password']
            account['salt'] = password_data['salt']
        if url is not None:
            account['url'] = url
        if notes is not None:
            account['notes'] = notes
        if category is not None and category in self.categories:
            account['category'] = category
        
        account['modified_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.save_vault()
        
        return True
    
    def delete_account(self, account_id: str):
        """Delete an account from the vault."""
        if account_id not in self.accounts:
            raise ValueError("Account not found")
        
        del self.accounts[account_id]
        self.save_vault()
    
    def get_account(self, account_id: str) -> dict:
        """Get a specific account by ID."""
        if account_id not in self.accounts:
            raise ValueError("Account not found")
        
        account_copy = self.accounts[account_id].copy()
        account_copy['id'] = account_id
        # Ensure all necessary fields are included
        for field in ['encrypted_password', 'salt', 'password_hash']:
            if field not in account_copy and field in self.accounts[account_id]:
                account_copy[field] = self.accounts[account_id][field]
        return account_copy
    
    def get_all_accounts(self) -> List[dict]:
        """Get all accounts with their IDs."""
        accounts_list = []
        for account_id, account_data in self.accounts.items():
            account_copy = account_data.copy()
            account_copy['id'] = account_id
            # Ensure all necessary fields are included
            for field in ['encrypted_password', 'salt', 'password_hash']:
                if field not in account_copy and field in account_data:
                    account_copy[field] = account_data[field]
            accounts_list.append(account_copy)
        
        return sorted(accounts_list, key=lambda x: x['service'].lower())
    
    def search_accounts(self, query: str) -> List[dict]:
        """
        Search accounts by service name, username, or URL.
        
        Args:
            query: Search query string
            
        Returns:
            List of matching accounts
        """
        if not query:
            return self.get_all_accounts()
        
        query_lower = query.lower()
        results = []
        
        for account_id, account_data in self.accounts.items():
            # Search in service name, username, and URL
            if (query_lower in account_data['service'].lower() or
                query_lower in account_data['username'].lower() or
                query_lower in account_data.get('url', '').lower()):
                
                account_copy = account_data.copy()
                account_copy['id'] = account_id
                # Ensure all necessary fields are included
                for field in ['encrypted_password', 'salt', 'password_hash']:
                    if field not in account_copy and field in account_data:
                        account_copy[field] = account_data[field]
                results.append(account_copy)
        
        return sorted(results, key=lambda x: x['service'].lower())
    
    def get_accounts_by_category(self, category: str) -> List[dict]:
        """Get all accounts in a specific category."""
        results = []
        
        for account_id, account_data in self.accounts.items():
            if account_data['category'] == category:
                account_copy = account_data.copy()
                account_copy['id'] = account_id
                # Ensure all necessary fields are included
                for field in ['encrypted_password', 'salt', 'password_hash']:
                    if field not in account_copy and field in account_data:
                        account_copy[field] = account_data[field]
                results.append(account_copy)
        
        return sorted(results, key=lambda x: x['service'].lower())
    
    def copy_to_clipboard(self, text: str, clear_after: int = None):
        """
        Copy text to clipboard and optionally clear after specified time.
        
        Args:
            text: Text to copy
            clear_after: Seconds after which to clear clipboard (default from settings)
        """
        try:
            pyperclip.copy(text)
            
            if clear_after is None:
                clear_after = self.settings.get('clipboard_clear_time', 30)
            
            # Schedule clipboard clearing (simplified - in real app would use threading)
            # For now, we'll just copy the text without auto-clearing
            
        except Exception as e:
            raise Exception(f"Failed to copy to clipboard: {str(e)}")
    
    def generate_password(self, length: int = 16, **kwargs) -> str:
        """Generate a secure password using the encryption module."""
        return self.encryption.generate_password(length, **kwargs)
    
    def check_password_strength(self, password: str) -> dict:
        """Check password strength using the encryption module."""
        return self.encryption.check_password_strength(password)
    
    def _create_backup(self):
        """Create a backup of the current vault."""
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(self.backup_dir, f'vault_backup_{timestamp}.json')
            
            shutil.copy2(self.vault_file, backup_file)
            
            # Keep only the last 10 backups
            self._cleanup_old_backups()
            
        except Exception as e:
            print(f"Warning: Failed to create backup: {str(e)}")
    
    def _cleanup_old_backups(self):
        """Remove old backup files, keeping only the latest 10."""
        try:
            if not os.path.exists(self.backup_dir):
                return
            
            backup_files = []
            for filename in os.listdir(self.backup_dir):
                if filename.startswith('vault_backup_') and filename.endswith('.json'):
                    filepath = os.path.join(self.backup_dir, filename)
                    backup_files.append((filepath, os.path.getmtime(filepath)))
            
            # Sort by modification time (newest first)
            backup_files.sort(key=lambda x: x[1], reverse=True)
            
            # Remove old backups (keep only 10)
            for filepath, _ in backup_files[10:]:
                os.remove(filepath)
                
        except Exception as e:
            print(f"Warning: Failed to cleanup old backups: {str(e)}")
    
    def export_data(self, export_file: str, include_passwords: bool = False):
        """
        Export data to a file (CSV or JSON format).
        
        Args:
            export_file: Path to export file
            include_passwords: Whether to include passwords in export
        """
        try:
            accounts_list = self.get_all_accounts()
            
            if export_file.lower().endswith('.csv'):
                import csv
                
                with open(export_file, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = ['service', 'username', 'url', 'category', 'notes']
                    if include_passwords:
                        fieldnames.insert(2, 'password')
                    
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for account in accounts_list:
                        row = {field: account.get(field, '') for field in fieldnames}
                        writer.writerow(row)
            
            elif export_file.lower().endswith('.json'):
                export_data = {
                    'exported_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'accounts': []
                }
                
                for account in accounts_list:
                    account_export = {
                        'service': account['service'],
                        'username': account['username'],
                        'url': account.get('url', ''),
                        'category': account['category'],
                        'notes': account.get('notes', '')
                    }
                    
                    if include_passwords:
                        account_export['password'] = account['password']
                    
                    export_data['accounts'].append(account_export)
                
                with open(export_file, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            else:
                raise ValueError("Export file must have .csv or .json extension")
                
        except Exception as e:
            raise Exception(f"Failed to export data: {str(e)}")
    
    def import_data(self, import_file: str):
        """
        Import data from a CSV or JSON file.
        
        Args:
            import_file: Path to import file
            
        Returns:
            Number of accounts imported
        """
        try:
            imported_count = 0
            
            if import_file.lower().endswith('.csv'):
                import csv
                
                with open(import_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        service = row.get('service', '').strip()
                        username = row.get('username', '').strip()
                        password = row.get('password', '').strip()
                        
                        if service and username and password:
                            self.add_account(
                                service=service,
                                username=username,
                                password=password,
                                url=row.get('url', '').strip(),
                                notes=row.get('notes', '').strip(),
                                category=row.get('category', 'Other').strip()
                            )
                            imported_count += 1
            
            elif import_file.lower().endswith('.json'):
                with open(import_file, 'r', encoding='utf-8') as f:
                    import_data = json.load(f)
                
                accounts = import_data.get('accounts', [])
                for account in accounts:
                    service = account.get('service', '').strip()
                    username = account.get('username', '').strip()
                    password = account.get('password', '').strip()
                    
                    if service and username and password:
                        self.add_account(
                            service=service,
                            username=username,
                            password=password,
                            url=account.get('url', '').strip(),
                            notes=account.get('notes', '').strip(),
                            category=account.get('category', 'Other').strip()
                        )
                        imported_count += 1
            
            else:
                raise ValueError("Import file must have .csv or .json extension")
            
            return imported_count
            
        except Exception as e:
            raise Exception(f"Failed to import data: {str(e)}")
    
    def get_categories(self) -> List[str]:
        """Get list of available categories."""
        return self.categories.copy()
    
    def add_category(self, category: str):
        """Add a new category."""
        if category and category not in self.categories:
            self.categories.append(category)
            self.save_vault()
    
    def get_settings(self) -> dict:
        """Get current settings."""
        return self.settings.copy()
    
    def update_settings(self, **kwargs):
        """Update settings."""
        self.settings.update(kwargs)
        self.save_vault()
    
    def get_vault_stats(self) -> dict:
        """Get vault statistics."""
        total_accounts = len(self.accounts)
        categories_count = {}
        
        for account in self.accounts.values():
            category = account['category']
            categories_count[category] = categories_count.get(category, 0) + 1
        
        return {
            'total_accounts': total_accounts,
            'categories_count': categories_count,
            'vault_file_size': os.path.getsize(self.vault_file) if os.path.exists(self.vault_file) else 0
        }
    
    def _restore_from_latest_backup(self):
        """Attempt to restore vault from the latest backup."""
        try:
            if not os.path.exists(self.backup_dir):
                raise Exception("No backup directory found")
            
            # Get list of backup files
            backup_files = [f for f in os.listdir(self.backup_dir) 
                           if f.startswith('vault_backup_') and f.endswith('.json')]
            
            if not backup_files:
                raise Exception("No backup files found")
            
            # Sort by timestamp (newest first)
            backup_files.sort(reverse=True)
            
            # Try each backup file until one works
            for backup_file in backup_files:
                backup_path = os.path.join(self.backup_dir, backup_file)
                try:
                    # Verify backup file
                    with open(backup_path, 'r') as f:
                        json.load(f)
                    
                    # Copy backup to vault file
                    shutil.copy2(backup_path, self.vault_file)
                    print(f"Restored vault from backup: {backup_file}")
                    return
                    
                except Exception:
                    continue
            
            raise Exception("All backup files are corrupted")
            
        except Exception as e:
            raise Exception(f"Failed to restore from backup: {str(e)}")
    
    def reload_vault(self):
        """Public method to reload vault data from file."""
        try:
            self.save_vault()  # Save any pending changes first
            self._load_vault()  # Then reload from file
        except Exception as e:
            raise Exception(f"Failed to reload vault: {str(e)}")
    
    def verify_master_password_and_decrypt(self, account_id: str, master_password: str) -> tuple[bool, Optional[str]]:
        """
        Verify master password and decrypt account password.
        
        Args:
            account_id: The account ID
            master_password: The master password to verify
            
        Returns:
            Tuple of (is_valid, decrypted_password)
        """
        try:
            # Get account data first
            account = self.accounts.get(account_id)
            if not account:
                return False, None
            
            # Load master password data
            master_file = os.path.join('data', 'master.json')
            with open(master_file, 'r') as f:
                master_data = json.load(f)
            
            # Verify master password
            is_valid = self.encryption.verify_master_password(
                master_password,
                master_data['password_hash'],
                master_data['salt']
            )
            
            if not is_valid:
                return False, None
            
            # Decrypt the password using the master password
            try:
                key = self.encryption._derive_key(
                    master_password, 
                    base64.b64decode(account['salt'].encode('utf-8'))
                )
                f = Fernet(key)
                encrypted_bytes = base64.b64decode(account['encrypted_password'].encode('utf-8'))
                decrypted_password = f.decrypt(encrypted_bytes).decode()
                return True, decrypted_password
                
            except Exception as e:
                print(f"Decryption error: {str(e)}")
                return False, None
            
        except Exception as e:
            print(f"Verification error: {str(e)}")
            return False, None 