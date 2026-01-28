# Fortify-on-Demand-Application-Security-as-a-Service-AppSec-SaaS-
# Fortify on Demand - Free Trial Experience & SAST Implementation Guide

## Table of Contents
- [Overview](#overview)
- [What is Fortify on Demand](#what-is-fortify-on-demand)
- [Free Trial Setup](#free-trial-setup)
- [Static Application Security Testing (SAST)](#static-application-security-testing-sast)
- [Repository Scan Results](#repository-scan-results)
- [Vulnerability Analysis](#vulnerability-analysis)
- [Remediation Process](#remediation-process)
- [Best Practices](#best-practices)
- [Resources](#resources)

---

## Overview

This document provides a comprehensive guide on utilizing Fortify on Demand's free trial for Static Application Security Testing (SAST). It covers the complete journey from initial setup through vulnerability discovery and remediation.

### Purpose
- Document the free trial registration and setup process
- Explain how SAST was implemented on our codebase
- Detail the vulnerabilities discovered during scanning
- Provide guidance for remediation efforts

---

## What is Fortify on Demand

Fortify on Demand is a Software-as-a-Service (SaaS) application security testing platform that provides comprehensive security analysis capabilities.

### Key Capabilities

#### Static Application Security Testing (SAST)
**SAST** Static Application Security Testing (SAST) inspects the application source or binary code for insecure coding patterns that lead to vulnerabilities. As it works at the code level, SAST can be used at the early stages of application development to ensure vulnerabilities are found even before the application development is completed. Our static tests use Fortify SCA, the industry leading SAST tool
This is a list of all scans for a given release. You can also import scans from other sources, such as Fortify SCA or WebInspect on-premise, to give you a single view of application security risk.


**Core Features:**
- **Early Detection**: Identifies security issues during development, not just in production
- **Code-Level Analysis**: Examines source code and compiled binaries
- **Pre-Deployment Security**: Finds vulnerabilities before application completion
- **Industry-Leading Tool**: Powered by Fortify SCA (Static Code Analyzer)

#### Centralized Scan Management
The platform provides a unified view of all security scans for a given release:
- View all scans for a specific application release
- Import scans from external sources:
  - Fortify SCA (on-premise installations)
  - WebInspect (on-premise installations)
  - Other compatible security scanning tools
- Single consolidated view of application security risk

---

## Free Trial Setup

### Step 1: Registration
1. Visit the Fortify on Demand website
2. Navigate to the free trial signup page
3. Complete the registration form with:
   - Company information
   - Contact details
   - Project requirements
   - Intended use case

### Step 2: Account Activation
1. Verify email address through confirmation link
2. Log in to the Fortify on Demand portal
3. Complete initial profile setup
4. Review trial limitations and features

### Step 3: Trial Features Available
The free trial typically includes:
- Limited number of scans (varies by trial offer)
- Access to SAST scanning capabilities
- Dashboard and reporting features
- Basic remediation guidance
- Technical support during trial period

### Step 4: Project Configuration
1. Create a new application in the portal
2. Define application metadata:
   - Application name
   - Technology stack
   - Business criticality
   - Compliance requirements

---

## Static Application Security Testing (SAST)

### How SAST Works

SAST analyzes your application's source code or compiled binaries without executing the program. This "white-box" testing approach provides:

1. **Comprehensive Coverage**: Analyzes 100% of code paths
2. **Early Feedback**: Identifies issues during development
3. **Root Cause Analysis**: Pinpoints exact file and line number
4. **Fix Guidance**: Provides remediation recommendations

### SAST Scan Process

#### 1. Code Preparation
```bash
# Clone the repository
git clone https://github.com/yakmatic-dev/Fortify-on-Demand-Application-Security-as-a-Service-AppSec-SaaS-.git

# Navigate to project directory
cd Fortify-on-Demand-Application-Security-as-a-Service-AppSec-SaaS-
```

#### 2. Scan Configuration
- **Language Detection**: Fortify automatically identifies programming languages
- **Scan Scope**: Define which files/directories to include
- **Ruleset Selection**: Choose security standards to test against:
  - OWASP Top 10
  - CWE/SANS Top 25
  - PCI-DSS requirements
  - Custom organizational policies

#### 3. Upload Methods

**Option A: Manual Upload via Web Interface**
1. Log in to Fortify on Demand portal
2. Navigate to your application
3. Click "Start Scan"
4. Upload source code as ZIP file
5. Configure scan settings
6. Submit scan

<img width="1906" height="757" alt="image" src="https://github.com/user-attachments/assets/1c47ff5b-e5ec-42b2-a9a6-df5968acf875" />

<img width="1919" height="950" alt="image" src="https://github.com/user-attachments/assets/65e6307d-117c-4410-875e-1600aeeebd5d" />


**Option B: CI/CD Integration**
```yaml
# Example GitHub Actions workflow
name: Fortify SAST Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
      steps:    
      - name: Check out source code
        uses: actions/checkout@v4  
      - name: Run Fortify on Demand SAST & SCA Scan
        uses: fortify/github-action@v2
        with:
          sast-scan: true
          debricked-sca-scan: true
        env:
          FOD_URL: https://ams.fortify.com
          FOD_TENANT: ${{secrets.FOD_TENANT}}
          FOD_USER: ${{secrets.FOD_USER}}
          FOD_PASSWORD: ${{secrets.FOD_PAT}}
          
```

#### 4. Scan Execution
- Fortify SCA analyzes the code
- Processing time varies based on:
  - Code size (lines of code)
  - Complexity
  - Number of files
  - Language(s) used

#### 5. Results Generation
- Vulnerability report generated
- Findings categorized by severity
- Detailed remediation guidance provided

---

## Repository Scan Results

### Scanned Repository
**Repository URL**: `https://github.com/yakmatic-dev/Fortify-on-Demand-Application-Security-as-a-Service-AppSec-SaaS-.git`

### Scan Summary

| Metric | Details |
|--------|---------|
| **Scan Date** | [Insert Date] |
| **Scan Type** | Static Application Security Testing (SAST) |
| **Tool Used** | Fortify SCA |
| **Total Issues Found** | [Insert Number] |
| **Critical** | [Insert Number] |
| **High** | [Insert Number] |
| **Medium** | [Insert Number] |
| **Low** | [Insert Number] |

### Vulnerability Categories Discovered

<img width="1918" height="939" alt="image" src="https://github.com/user-attachments/assets/9dd7509d-d103-49f7-8367-57a15677073a" />

<img width="1904" height="948" alt="image" src="https://github.com/user-attachments/assets/0d4c8e97-a46b-4ee2-b047-dd57f472d453" />

<img width="1917" height="942" alt="image" src="https://github.com/user-attachments/assets/ecfbf289-0c63-4f65-a0c6-c890aa7160fb" />

<img width="1919" height="945" alt="image" src="https://github.com/user-attachments/assets/7dbbe0df-8738-4760-ab49-9ae0b234932b" />

<img width="1903" height="944" alt="image" src="https://github.com/user-attachments/assets/7cc9be56-e614-4caa-84db-8aa0bf942983" />

<img width="1911" height="938" alt="image" src="https://github.com/user-attachments/assets/cc031a9c-ae9b-4d00-89fc-f43a182a90f6" />

<img width="1919" height="941" alt="image" src="https://github.com/user-attachments/assets/545ceb04-5650-4609-b9c2-1f459b5333fe" />

<img width="1919" height="944" alt="image" src="https://github.com/user-attachments/assets/4966f349-5e0b-4f2e-9489-422e4aa01e2b" />

<img width="1917" height="947" alt="image" src="https://github.com/user-attachments/assets/c619aec3-6ec0-4c57-8f6f-2a0e16a7141e" />

<img width="1914" height="953" alt="image" src="https://github.com/user-attachments/assets/243f0002-c92b-49c9-bcf1-e2455d138f6a" />

<img width="1915" height="947" alt="image" src="https://github.com/user-attachments/assets/a82ff5a3-cd95-497e-8c8a-f23882d092df" />




<img width="1919" height="942" alt="image" src="https://github.com/user-attachments/assets/f509a2eb-9180-424a-afd2-011cbd7c6975" />





<img width="1912" height="946" alt="image" src="https://github.com/user-attachments/assets/4ea2d4aa-727e-40db-a328-570057f23a3e" />



<img width="1911" height="940" alt="image" src="https://github.com/user-attachments/assets/d51aa8bf-b20b-4e21-a519-b9bd3c28f90a" />



Based on typical SAST findings, several vulnerabilities were found 


#### Risk-Based Prioritization
1. **Critical & High Severity**
   - Address immediately
   - Focus on publicly accessible code
   - Prioritize authentication/authorization issues

2. **Medium Severity**
   - Schedule for next sprint
   - Evaluate business impact
   - Consider compensating controls

3. **Low Severity**
   - Add to backlog
   - Address during refactoring
   - May accept risk if properly documented

#### OWASP Risk Rating
Consider these factors:
- **Exploitability**: How easy is it to exploit?
- **Prevalence**: How common is this vulnerability type?
- **Detectability**: Can attackers easily find it?
- **Technical Impact**: What's the worst-case scenario?
- **Business Impact**: How does this affect the organization?

### Phase 2: Verification

Before fixing, verify each finding:

1. **Reproduce the Issue**
   - Confirm the vulnerability exists
   - Understand the attack vector
   - Document the exploit scenario

2. **Assess False Positives**
   - Some findings may be false positives
   - Review code context carefully
   - Consult with development team
   - Mark false positives in Fortify

3. **Determine Scope**
   - Is this a one-off issue or pattern?
   - Are there similar issues elsewhere?
   - Should this be a code-wide fix?

### Phase 3: Remediation

#### General Remediation Strategies

- Collaborate with the developers and ensure improvemnet on the source code 


### Phase 4: Testing

After remediation:

1. **Unit Tests**
   - Test security fixes
   - Ensure functionality not broken
   - Add security-specific test cases

2. **Regression Testing**
   - Verify fix doesn't introduce new issues
   - Test related functionality

3. **Re-scan**
   - Run another Fortify scan
   - Verify issues are resolved
   - Check for new findings

### Phase 5: Documentation

Document all remediation efforts:

```markdown
## Vulnerability Fix Log

### Issue: SQL Injection in User Login (FOD-2024-001)
- **Date Identified**: 2024-01-15
- **Severity**: Critical
- **File**: src/auth/login.py, Line 45
- **Description**: User input directly concatenated into SQL query
- **Fix Applied**: Implemented parameterized queries using prepared statements
- **Developer**: John Doe
- **Reviewer**: Jane Smith
- **Date Fixed**: 2024-01-16
- **Verification**: Re-scan clear on 2024-01-17
```

---

## Best Practices

### Development Practices

#### 1. Shift-Left Security
- Integrate SAST early in SDLC
- Run scans on every commit (CI/CD)
- Train developers on secure coding

#### 2. Secure Coding Standards
Adopt frameworks like:
- **OWASP Secure Coding Practices**
- **CERT Secure Coding Standards**
- **Language-specific guidelines** (e.g., Python Security Best Practices)

#### 3. Code Review Process
```
Pull Request Checklist:
□ Code follows secure coding standards
□ No hard-coded credentials
□ Input validation implemented
□ Output encoding applied
□ Error handling doesn't expose sensitive data
□ Dependencies are up to date
□ Unit tests include security test cases
```

#### 4. Defense in Depth
Implement multiple security layers:
- Input validation
- Output encoding
- Authentication & Authorization
- Encryption
- Logging & Monitoring
- Security headers

### Fortify Best Practices

#### 1. Regular Scanning Schedule
- **Daily**: Automated scans on development branches
- **Weekly**: Full scans on integration branches
- **Pre-Release**: Comprehensive scan before deployment

#### 2. Baseline and Track
- Establish security baseline
- Track metrics over time:
  - Total vulnerabilities
  - New vs. resolved issues
  - Mean time to remediate
  - Vulnerability density (issues per KLOC)

#### 3. Custom Rules
- Create organization-specific security rules
- Enforce internal coding standards
- Address unique business logic vulnerabilities

#### 4. Integration Points
Integrate Fortify with:
- **JIRA**: Auto-create tickets for vulnerabilities
- **Slack/Teams**: Notify on critical findings
- **IDE Plugins**: Real-time feedback to developers
- **CI/CD Pipelines**: Automated scanning

### Continuous Improvement

#### 1. Metrics to Track
```
Security Metrics Dashboard:
- Total vulnerabilities: [Current Count]
- Trend: [Up/Down/Stable]
- Critical/High issues: [Count]
- Mean time to detect: [X days]
- Mean time to remediate: [Y days]
- False positive rate: [Z%]
- Scan coverage: [% of codebase]
```

#### 2. Regular Training
- Quarterly security training for developers
- Lunch-and-learn sessions on common vulnerabilities
- Capture the Flag (CTF) exercises
- Secure coding workshops

#### 3. Feedback Loop
- Developers provide feedback on findings
- Security team refines rules and policies
- Share lessons learned across teams

---

## Resources

### Official Documentation
- [Fortify on Demand Portal](https://www.microfocus.com/en-us/products/application-security-testing/overview)
- [Fortify SCA Documentation](https://www.microfocus.com/documentation/fortify-static-code-analyzer/)
- [Fortify Community](https://community.microfocus.com/cyberres/fortify/)

### Security Standards
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)

### Learning Resources
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Practice identifying and fixing vulnerabilities
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free online training
- [Secure Code Warrior](https://www.securecodewarrior.com/) - Gamified secure coding training

### Tools and Libraries

#### Input Validation
- Python: `validators`, `cerberus`
- JavaScript: `validator.js`, `joi`
- Java: `Hibernate Validator`, `Apache Commons Validator`

#### Output Encoding
- JavaScript: `DOMPurify`, `xss`
- Python: `bleach`, `MarkupSafe`
- Java: `OWASP Java Encoder`

#### Security Headers
- Python (Flask): `flask-talisman`
- Node.js: `helmet`
- Java (Spring): Spring Security defaults

#### Dependency Scanning
- `npm audit` (Node.js)
- `pip-audit` (Python)
- `OWASP Dependency-Check`
- GitHub Dependabot

---

## Next Steps

### Immediate Actions
1. ✅ Complete free trial registration
2. ✅ Scan repository
3. ⬜ Review all Critical and High severity findings
4. ⬜ Create remediation tickets
5. ⬜ Assign owners to each vulnerability
6. ⬜ Set target remediation dates

### Short-term Goals (1-3 months)
- Remediate all Critical vulnerabilities
- Address 80% of High severity issues
- Establish CI/CD integration
- Train development team on secure coding
- Implement security code review process

### Long-term Goals (3-12 months)
- Achieve <10 High/Critical vulnerabilities
- Reduce mean time to remediate to <7 days
- Integrate SAST into IDE for real-time feedback
- Establish security champions program
- Achieve compliance with relevant standards (PCI-DSS, SOC 2, etc.)

---

## Appendix

### Common Vulnerability Fixes by Language

#### Python (Django/Flask)
```python
# SQL Injection Prevention
from django.db import connection
cursor = connection.cursor()
cursor.execute("SELECT * FROM users WHERE username = %s", [username])

# XSS Prevention (Django auto-escapes)
# In templates, use |safe only when absolutely necessary
{{ user_input }}  # Auto-escaped

# CSRF Protection (Django)
# Enable CSRF middleware and use {% csrf_token %} in forms

# Secure File Upload
from django.core.files.uploadedfile import UploadedFile
from pathlib import Path

def handle_upload(file: UploadedFile):
    # Validate file type
    allowed_types = ['image/jpeg', 'image/png']
    if file.content_type not in allowed_types:
        raise ValueError("Invalid file type")
    
    # Validate file size
    if file.size > 5 * 1024 * 1024:  # 5MB
        raise ValueError("File too large")
    
    # Sanitize filename
    safe_name = Path(file.name).name
```

#### JavaScript (Node.js/Express)
```javascript
// SQL Injection Prevention
const mysql = require('mysql2/promise');
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE username = ?',
  [username]
);

// XSS Prevention
const xss = require('xss');
const clean = xss(userInput);

// CSRF Protection
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

// Secure Headers
const helmet = require('helmet');
app.use(helmet());

// Input Validation
const { body, validationResult } = require('express-validator');
app.post('/user',
  body('email').isEmail(),
  body('age').isInt({ min: 0, max: 120 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Process valid data
  }
);
```

#### Java (Spring Boot)
```java
// SQL Injection Prevention
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.username = :username")
    User findByUsername(@Param("username") String username);
}

// XSS Prevention
import org.owasp.encoder.Encode;
String safe = Encode.forHtml(userInput);

// CSRF Protection (Spring Security)
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        return http.build();
    }
}

// Input Validation
import javax.validation.constraints.*;
public class UserDTO {
    @NotBlank
    @Email
    private String email;
    
    @Min(0)
    @Max(120)
    private Integer age;
}
```

### Glossary

- **SAST**: Static Application Security Testing - analyzes source code without executing it
- **DAST**: Dynamic Application Security Testing - tests running applications
- **SCA**: Software Composition Analysis - identifies vulnerabilities in third-party components
- **IAST**: Interactive Application Security Testing - combines SAST and DAST
- **CWE**: Common Weakness Enumeration - catalog of software weaknesses
- **CVE**: Common Vulnerabilities and Exposures - list of publicly disclosed vulnerabilities
- **CVSS**: Common Vulnerability Scoring System - standardized severity rating
- **SDL**: Security Development Lifecycle - Microsoft's security assurance process
- **DevSecOps**: Integration of security practices into DevOps

---

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2024-01-28 | Initial documentation | [Your Name] |

---

## Contact Information

For questions or issues related to this security initiative:

- **Security Team**:yakubiliyas12@gmail.com
- **DevOps Team**: devops@yourcompany.com
- **Fortify Support**: support.fortify@microfocus.com

---

**Document Status**: Living Document - Updated as new vulnerabilities are discovered and remediated

