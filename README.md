# Personal Password Manager

A secure, feature-rich password manager application built with Python and Tkinter. This application provides enterprise-grade security for personal password management with an intuitive graphical interface.

## 🔐 Features

### Security
- **AES-256-GCM Encryption**: Military-grade encryption for all stored passwords
- **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256 for master password hashing
- **Salt-based Security**: Unique salts for each encrypted field
- **Master Password Protection**: Single master password protects all data
- **Session Timeout**: Automatic logout after configurable inactivity period
- **Login Attempt Limiting**: Protection against brute force attacks

### Password Management
- **Secure Storage**: Encrypted vault for unlimited password accounts
- **Password Generator**: Customizable secure password generation
- **Password Strength Checker**: Real-time password strength analysis
- **Categories**: Organize accounts by type (Banking, Social Media, etc.)
- **Search Functionality**: Quick search across service names and usernames
- **Auto-backup**: Automatic encrypted backups with retention

### User Interface
- **Modern GUI**: Clean, intuitive Tkinter-based interface
- **Account Management**: Easy add, edit, delete, and view operations
- **Quick Actions**: Copy username/password with single click
- **Keyboard Shortcuts**: Power-user keyboard navigation
- **Right-click Menus**: Context-sensitive actions
- **Responsive Design**: Resizable interface with proper scaling

### Import/Export
- **CSV Import**: Import from other password managers
- **JSON Export**: Structured data export with optional password inclusion
- **Backup Management**: Automatic backup creation and cleanup
- **Data Migration**: Easy migration from other password managers

## 📋 Requirements

- Python 3.7 or higher
- Windows, macOS, or Linux operating system
- 50MB free disk space
- Internet connection (for initial dependency installation only)

## 🚀 Installation

### 1. Clone or Download

```bash
git clone <repository-url>
cd password_manager
```

Or download and extract the ZIP file.

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Application

```bash
python main.py
```

## 📖 Usage Guide

### First-Time Setup

1. **Run the Application**: Execute `python main.py`
2. **Create Master Password**: You'll be prompted to create a master password
   - Minimum 8 characters
   - Include uppercase, lowercase, numbers, and symbols
   - The stronger the password, the more secure your data
3. **Confirm Password**: Enter the password twice to confirm
4. **Complete Setup**: The application will create your encrypted vault

### Daily Usage

#### Logging In
1. Enter your master password
2. Click "Login" or press Enter
3. Failed attempts are limited for security

#### Adding Accounts
1. Click "Add New Account" button
2. Fill in required fields:
   - **Service Name**: Name of the service (e.g., "Facebook")
   - **Username/Email**: Your login username or email
   - **Password**: The account password
3. Optional fields:
   - **Website URL**: Direct link to login page
   - **Notes**: Additional information
   - **Category**: Organize by type
4. Click "Add Account" to save

#### Managing Accounts
- **View Password**: Double-click account or use "View Password" button
- **Edit Account**: Right-click → "Edit Account" or press F2
- **Delete Account**: Right-click → "Delete Account" or press Delete
- **Copy Username**: Right-click → "Copy Username"
- **Copy Password**: Right-click → "Copy Password"
- **Open URL**: Right-click → "Open URL" (opens in default browser)

#### Search and Filter
- **Search**: Type in the search box to filter accounts
- **Categories**: Click category in sidebar to filter
- **Clear Search**: Click "Clear" button or select "All" category

#### Password Generation
1. Click "Generate Password" in header or during account creation
2. Adjust settings:
   - **Length**: 8-128 characters
   - **Character Types**: Include/exclude character sets
   - **Exclude Similar**: Avoid confusing characters (0, O, l, 1)
3. Click "Generate New" for different passwords
4. Click "Use This Password" to apply

### Advanced Features

#### Import Data
1. **File Menu**: Click "Import" in header
2. **Select File**: Choose CSV or JSON file
3. **Required Format**:
   - CSV: service, username, password, url, notes, category
   - JSON: Structured format with accounts array
4. **Confirm Import**: Review imported accounts

#### Export Data
1. **File Menu**: Click "Export" in header
2. **Choose Format**: Select CSV or JSON
3. **Password Option**: Choose whether to include passwords
4. **Select Location**: Choose save location
5. **Security Warning**: Exported passwords are in plain text

#### Settings Configuration
1. **Access Settings**: Click "Settings" in header
2. **Configure Options**:
   - **Auto-backup**: Enable/disable automatic backups
   - **Session Timeout**: Set inactivity timeout (5-60 minutes)
   - **Clipboard Clear**: Auto-clear clipboard after copying (10-300 seconds)
3. **Save Settings**: Click "Save Settings"

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | Add new account |
| `Ctrl+F` | Focus search field |
| `Ctrl+G` | Generate password |
| `Ctrl+Q` | Logout |
| `F2` | Edit selected account |
| `Delete` | Delete selected account |
| `Enter` | Confirm action in dialogs |
| `Escape` | Cancel dialog |

## 🛡️ Security Best Practices

### Master Password
- Use a unique, strong master password
- Never share your master password
- Consider using a passphrase (multiple words)
- Don't use the same password elsewhere

### Account Passwords
- Use the built-in password generator
- Enable all character types for maximum security
- Use unique passwords for each account
- Regularly update important passwords

### Data Protection
- Keep the application updated
- Store the application files securely
- Consider encrypting your entire system drive
- Regularly backup your vault

### Physical Security
- Lock your computer when away
- Don't leave the application open unattended
- Be aware of shoulder surfing
- Use privacy screens if needed

## 📁 File Structure

```
password_manager/
├── main.py              # Application entry point
├── setup_master.py      # Master password setup
├── password_manager.py  # Core password manager logic
├── encryption.py        # Encryption utilities
├── requirements.txt     # Python dependencies
├── README.md           # This file
├── ui/                 # User interface components
│   ├── __init__.py
│   ├── login_window.py # Login interface
│   ├── main_window.py  # Main application window
│   └── dialogs.py      # Dialog windows
└── data/               # Data storage (created automatically)
    ├── master.json     # Master password hash
    ├── vault.json      # Encrypted password vault
    └── backups/        # Automatic backups
```

## 🔧 Troubleshooting

### Common Issues

#### "Failed to import required modules"
**Solution**: Install dependencies with `pip install -r requirements.txt`

#### "Master password not found"
**Solution**: Delete `data/master.json` to reset and create new master password

#### "Failed to decrypt account"
**Solution**: This usually indicates data corruption. Restore from backup if available.

#### Application won't start
**Solutions**:
1. Check Python version: `python --version` (need 3.7+)
2. Verify all dependencies: `pip list`
3. Check file permissions in application directory

#### Clipboard not working
**Solution**: Install/update pyperclip: `pip install --upgrade pyperclip`

### Performance Issues

- Large vaults (1000+ accounts) may experience slower load times
- Search is optimized but may take time with very large datasets
- Consider archiving old/unused accounts

### Data Recovery

#### Backup Restoration
1. Close the application
2. Navigate to `data/backups/` folder
3. Copy desired backup file
4. Rename to `vault.json`
5. Replace the current `data/vault.json`
6. Restart application

#### Manual Data Recovery
If vault is corrupted but readable:
1. Export data immediately
2. Create new master password setup
3. Import the exported data

## 🔒 Security Architecture

### Encryption Details
- **Algorithm**: AES-256 in GCM mode
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000 (configurable)
- **Salt**: Unique 128-bit salt per encrypted field
- **Nonce**: Unique 96-bit nonce per encryption operation

### Data Storage
- Master password: Salted hash stored in `master.json`
- Account data: Individually encrypted in `vault.json`
- No plaintext passwords ever stored
- Automatic secure key cleanup in memory

### Authentication
- Master password verification through hash comparison
- Failed attempt tracking with lockout
- Session timeout for idle protection
- No password recovery mechanism (by design)

## 📄 License

This project is released under the MIT License. See LICENSE file for details.

## 🤝 Contributing

This is a personal password manager designed for individual use. While contributions are not actively sought, feedback and suggestions are welcome.

## ⚠️ Disclaimer

This software is provided "as is" without warranty. Users are responsible for:
- Remembering their master password (no recovery available)
- Maintaining secure backups of their data
- Keeping the application and system secure
- Complying with applicable laws and regulations

## 📞 Support

For issues or questions:
1. Check this README for common solutions
2. Verify all dependencies are properly installed
3. Ensure you're using a supported Python version
4. Check file and directory permissions

## 🔄 Version History

### v1.0.0 (Current)
- Initial release
- Complete password manager functionality
- AES-256 encryption
- Full GUI interface
- Import/export capabilities
- Backup system
- Password generation
- Category management
- Search functionality 