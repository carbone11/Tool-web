# 🖥️ CyberSec Web Testing Tool - Professional CLI Guide

**Complete User Manual for Professional Security Interface**  
*Created by snaken18*

---

## 🚀 Quick Start

### Launch the Professional Interface

```bash
# Direct Python execution
python menu_cli.py

# Platform-specific launchers
.\launch_menu.ps1    # Windows PowerShell
.\launch_menu.bat    # Windows Batch
./launch_menu.sh     # Linux/macOS
```

### Professional Interface Overview

The new professional CLI interface features:
- **Terminal-compatible design**: No emoji dependencies, pure ASCII
- **ANSI color support**: Professional color coding for all terminal types
- **Clean visual structure**: Clear sections and intuitive navigation
- **snaken18 branding**: Professional signature integration
- **Legal compliance**: Built-in authorization verification

---

## 📋 Main Menu Navigation

Upon launch, you'll see the professional banner:

```
================================================================================
                    CYBERSEC WEB TESTING TOOL v2.0
                     Professional Security Scanner
                           
                            Created by snaken18
                     Advanced Penetration Testing Suite
================================================================================

[!] LEGAL WARNING - AUTHORIZED TESTING ONLY [!]

This tool is designed EXCLUSIVELY for authorized security testing.
Unauthorized use may violate local, national, and international laws.
Users are solely responsible for compliance with applicable regulations.
```

### Menu Options

```
[*] MAIN MENU
==============================
[1] Configure Target URL
[2] Select Security Modules  
[3] Advanced Settings
[4] Report Configuration
[5] Execute Security Scan
[6] Help & Information
[0] Exit Program
==============================
```

---

## 🎯 1. Configure Target URL

### URL Configuration Process

1. **Access**: Select option `[1]` from main menu
2. **Examples provided**: The interface shows valid URL formats
3. **Input validation**: Automatic protocol addition if missing
4. **Legal verification**: **CRITICAL** authorization confirmation required

### Authorization Verification

```
 LEGAL AUTHORIZATION REQUIRED 

Target to configure: https://example.com

CRITICAL VERIFICATION:
  1. Do you have written authorization from the system owner?
  2. Are you the legitimate owner of this system?
  3. Do you understand the legal implications?

[?] Confirm authorization (yes/no):
```

### Supported URL Formats

- `https://example.com`
- `http://testsite.local`
- `https://app.company.com:8080`
- `192.168.1.100` (automatically adds http://)

---

## 🔧 2. Select Security Modules

### Available Security Modules

| Symbol | Module | Description |
|--------|--------|-------------|
| `[SQL]` | **SQL Injection Scanner** | Detecte les vulnerabilites d'injection SQL |
| `[XSS]` | **Cross-Site Scripting** | Detecte les failles XSS reflechies |
| `[HDR]` | **Security Headers Analysis** | Verifie les en-tetes de securite HTTP |
| `[PRT]` | **Port Scanner** | Decouvre les ports ouverts et services |
| `[DIR]` | **Directory Enumeration** | Enumere les fichiers et dossiers caches |

### Module Selection Interface

```
[*] MODULE SELECTION
========================================

[AVAILABLE MODULES]
[OFF] [1] [SQL] SQL Injection Scanner
      Detecte les vulnerabilites d'injection SQL
[OFF] [2] [XSS] Cross-Site Scripting (XSS)
      Detecte les failles XSS reflechies
[ON]  [3] [HDR] Security Headers Analysis
      Verifie les en-tetes de securite HTTP

[OPTIONS]
[A] Select All Modules
[C] Clear Selection  
[B] Back to Main Menu
```

### Selection Controls

- **Individual selection**: Enter module number (1-5)
- **Select all**: Enter `A`
- **Clear selection**: Enter `C`
- **Return to menu**: Enter `B`

---

## ⚙️ 3. Advanced Settings

### Configuration Options

```
[*] ADVANCED SETTINGS
========================================

[CURRENT SETTINGS]
[1] Threads: 10
[2] Timeout: 30s
[3] Verbose Mode: Disabled

[MODIFY SETTINGS]
[1] Thread Count
[2] Request Timeout
[3] Verbose Mode
[B] Back to Main Menu
```

### Thread Configuration

- **Range**: 1-50 threads
- **Recommendations**:
  - **Stealth scanning**: 1-5 threads
  - **Balanced approach**: 10-20 threads
  - **Aggressive scanning**: 20-50 threads

### Timeout Settings

- **Range**: 1-120 seconds
- **Recommendations**:
  - **Fast networks**: 10-15 seconds
  - **Standard scanning**: 20-30 seconds
  - **Slow/distant targets**: 30-60 seconds

---

## 📄 4. Report Configuration

### Report Format Options

```
[*] REPORT CONFIGURATION
========================================

[SUPPORTED FORMATS]
  .html - Complete HTML report with charts
  .json - Structured data for processing
  Leave empty for console output only
```

### Report Features

- **HTML Reports**: 
  - Visual dashboards
  - Vulnerability charts
  - Professional formatting
  - Embedded CSS/JavaScript

- **JSON Reports**:
  - Machine-readable format
  - API integration ready
  - Structured vulnerability data
  - Programmatic processing

- **Console Output**:
  - Real-time feedback
  - Immediate results
  - No file dependencies

---

## 🚀 5. Execute Security Scan

### Pre-Scan Verification

Before execution, the interface shows a comprehensive summary:

```
[*] SECURITY SCAN EXECUTION
========================================

[SCAN SUMMARY]
  Target: https://example.com
  Modules: sql, xss, headers
  Threads: 10
  Timeout: 30s

[?] Confirm scan execution? (yes/no):
```

### Real-Time Scan Progress

```
[*] SECURITY SCAN IN PROGRESS
==================================================

[SCANNING] [SQL] SQL Injection Scanner
  [ALERT] 2 vulnerability(ies) detected

[SCANNING] [XSS] Cross-Site Scripting (XSS)
  [CLEAN] No vulnerabilities found

[SCANNING] [HDR] Security Headers Analysis
  [ALERT] 3 vulnerability(ies) detected
```

### Scan Summary

```
[*] SCAN SUMMARY
==============================
  Total Vulnerabilities: 5
  Critical/High: 2
  Medium: 2
  Low/Info: 1

Scan completed by snaken18 CyberSec Tool
```

---

## ❓ 6. Help & Information

### Comprehensive Help System

The help section provides:

1. **Module Descriptions**: Detailed explanations of each security module
2. **Usage Recommendations**: Best practices for effective scanning
3. **Legal Considerations**: Important compliance information
4. **Technical Support**: Troubleshooting and support resources

### Professional Signature

All help content includes the snaken18 signature:

```
CyberSec Web Testing Tool v2.0 - Created by snaken18
Professional security testing for authorized environments
```

---

## 🛡️ Professional Best Practices

### Security Scanning Guidelines

1. **Authorization First**
   - Always obtain written permission
   - Verify system ownership
   - Understand legal implications

2. **Conservative Approach**
   - Start with header analysis
   - Use moderate thread counts
   - Monitor target resources

3. **Documentation**
   - Generate comprehensive reports
   - Maintain scan logs
   - Document findings properly

4. **Responsible Disclosure**
   - Follow industry standards
   - Report vulnerabilities ethically
   - Respect disclosure timelines

---

## 🔧 Technical Features

### Terminal Compatibility

- **ANSI Color Support**: Automatic detection and fallback
- **Cross-Platform**: Windows, Linux, macOS compatible
- **ASCII-Only Interface**: No Unicode dependencies
- **PowerShell Support**: Native Windows terminal support

### Error Handling

- **Graceful Degradation**: Continues operation on non-critical errors
- **User-Friendly Messages**: Clear error descriptions
- **Recovery Options**: Automatic retry mechanisms
- **Debug Information**: Detailed logging when enabled

### Performance Optimization

- **Concurrent Scanning**: Multi-threaded operation
- **Rate Limiting**: Respectful request patterns
- **Memory Management**: Efficient resource usage
- **Progress Tracking**: Real-time status updates

---

## 📞 Support & Contact

### Technical Support Resources

- **In-Application Help**: Comprehensive built-in documentation
- **README Documentation**: Complete project overview
- **Error Logs**: Detailed debugging information
- **Community Support**: Professional security discussions

### Professional Development

This tool represents professional-grade security testing software developed by **snaken18** for the cybersecurity community.

**Key Features:**
- Professional interface design
- Comprehensive security modules
- Legal compliance integration
- Industry-standard reporting

---

## 🏆 Professional Signature

```
================================================================================
                    CyberSec Web Testing Tool v2.0
                        Created by snaken18
                 Professional Security Testing Suite
================================================================================

"Use your cybersecurity knowledge ethically and responsibly."
```

*© 2024 snaken18 - Professional Security Testing Tools*