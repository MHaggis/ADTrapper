# ADTrapper: Enterprise Active Directory Security Analytics Platform

[![ADTrapper](https://img.shields.io/badge/ADTrapper-Enterprise--Security-blue?style=for-the-badge&logo=shield)](https://github.com/your-repo/ADTrapper)
[![AD CS Security](https://img.shields.io/badge/AD--CS--Security-ESC1--16-green?style=flat-square)](https://github.com/your-repo/ADTrapper)
[![SharpHound Integration](https://img.shields.io/badge/SharpHound--Integration-Full--Support-orange?style=flat-square)](https://github.com/BloodHoundAD/SharpHound)

## 🎯 Project Overview

**ADTrapper** is an enterprise-grade security analytics platform specifically designed for **Active Directory Certificate Services (AD CS) security assessment** and comprehensive **Windows Event Log analysis**. Built with modern security research and real-world threat intelligence, ADTrapper provides **50+ specialized rules** that detect AD CS vulnerabilities, privilege escalation attacks, and sophisticated Active Directory attack chains.

### 🚀 Key Features

- **🔐 Complete AD CS Security Coverage**: ESC1-ESC16 vulnerability detection with Locksmith-compatible analysis
- **🎯 SharpHound Integration**: Full BloodHound data analysis with attack path visualization
- **⚡ Real-Time Threat Detection**: Immediate anomaly detection during data upload and processing
- **🔍 Advanced Analytics Engine**: Machine learning-enhanced pattern recognition and risk scoring
- **🌐 Enterprise Integration**: SIEM-ready exports, API integrations, and compliance reporting
- **📊 Comprehensive Rule Engine**: 50+ specialized rules covering authentication, network, behavioral, and certificate security

### 🎯 Why ADTrapper Matters

In today's threat landscape, **Active Directory Certificate Services (AD CS)** has become a primary attack vector for advanced persistent threats. According to industry research:

- **90%+ of enterprise environments** have AD CS deployments
- **ESC1-ESC15 vulnerabilities** affect millions of certificates worldwide
- **Certificate-based attacks** bypass traditional security controls
- **AD CS misconfigurations** enable domain-wide privilege escalation

ADTrapper addresses these challenges by providing **continuous monitoring**, **real-time detection**, and **comprehensive analysis** of AD CS security posture, making it an essential tool for enterprise security teams and red team operators.

## 📊 Rules Overview

| Category | Count | Description | Key Threat Detection |
|----------|-------|-------------|---------------------|
| **Authentication & Authorization** | 15 | Login patterns, credential attacks, privilege escalation | Brute force, password spraying, golden tickets, pass-the-hash |
| **Network Security** | 5 | Geographic anomalies, IP-based attacks | Impossible travel, VPN/proxy abuse, C2 communications |
| **Behavioral Analysis** | 8 | User activity patterns, temporal analysis | Anomalous behavior, insider threats, automated attacks |
| **Certificate Services** | 9 | AD CS vulnerabilities, ESC1-ESC15 attacks | Certificate-based privilege escalation, AD CS misconfigurations |
| **Active Directory Security** | 13 | SharpHound data analysis, privilege escalation | Attack paths, delegation abuse, SID history exploitation |
| **Total** | **50+** | Comprehensive enterprise security coverage | Multi-vector threat detection |

## 🔍 Advanced Threat Detection Capabilities

### Industry Integration
- **SharpHound Integration**: Full support for BloodHound data collection and analysis
- **Locksmith Compatibility**: AD CS auditing aligned with Jake Hildreth's Locksmith tool
- **Event Log Analysis**: Comprehensive Windows security event processing
- **Real-time Analytics**: Immediate threat detection during data upload
- **Compliance Mapping**: NIST, MITRE ATT&CK, and CIS Controls alignment

### SharpHound Collection Method Analysis

ADTrapper analyzes data from all SharpHound collection methods:

#### **Default Collection Analysis**
- **Security Group Memberships**: Privilege escalation paths through group nesting
- **Domain Trusts**: Trust relationship vulnerabilities and attack paths
- **Abusable Rights**: Dangerous permissions on AD objects (WriteOwner, WriteDACL, etc.)
- **Group Policy Links**: GPO inheritance and application analysis
- **OU Structures**: Administrative boundary analysis
- **Local Admin Memberships**: Lateral movement opportunities via local admin rights
- **Active Sessions**: Current user session mapping for attack path identification

#### **Session Collection Analysis**
- **Real-time Session Tracking**: Live user session monitoring
- **Lateral Movement Paths**: Session-based attack vector identification
- **Administrative Session Detection**: Sessions with elevated privileges
- **Session Duration Analysis**: Anomalous session patterns

#### **Local Group Collection Analysis**
- **Administrators Group Analysis**: Local admin privilege mapping
- **RDP Group Membership**: Remote access privilege assessment
- **DCOM/RPC Group Analysis**: Distributed computing privilege evaluation
- **Remote Management Groups**: PowerShell remoting and WinRM access analysis

#### **ACL Collection Analysis**
- **Object Permission Analysis**: Dangerous ACE combinations
- **Inheritance Analysis**: Permission inheritance vulnerabilities
- **Principal Analysis**: User/group permission mappings
- **Rights Analysis**: GenericAll, WriteDACL, WriteOwner detection

#### **Trust Collection Analysis**
- **Trust Direction Analysis**: Bidirectional vs unidirectional trusts
- **Transitivity Analysis**: Forest-level trust implications
- **SID Filtering Status**: Trust security boundary assessment
- **Authentication Flow Analysis**: Kerberos trust path evaluation

---

## 🔐 Windows Event Log Rules

### Core Security Detection Rules

#### Brute Force Detection Rule
- **ID**: `brute_force_detection`
- **Category**: Authentication
- **Severity**: High
- **Windows Event IDs**: 4624 (Success), 4625 (Failure)
- **Detection Logic**:
  - **Single-User Brute Force**: ≥5 failed attempts per user within 10 minutes
  - **Distributed Attacks**: Same user from multiple IP addresses (≥2 IPs)
  - **High-Frequency Attacks**: >2 attempts per minute
  - **Credential Compromise Indicators**: Successful login after failed attempts
  - **Multi-User Attacks**: Single IP targeting multiple users
- **Industry Context**: Most common authentication attack (OWASP Top 10), often automated
- **Technical Implementation**:
  - Time window analysis (30-minute rolling window)
  - Source IP correlation and geolocation
  - Failure reason analysis (wrong password vs account disabled)
  - Computer target mapping and pattern recognition
  - Confidence scoring based on attack characteristics

#### Geographic Anomaly Rule
- **ID**: `geographic_anomaly_detection`
- **Category**: Network/Behavioral
- **Severity**: High
- **Windows Event IDs**: 4624, 4625, 4648, 4778, 4779
- **Detection Logic**:
  - **Multi-Country Access**: User logging from >2 countries within 2 hours
  - **Impossible Travel**: Travel requiring >1200 km/h (impossible for commercial flight)
  - **Suspicious Countries**: Access from high-risk countries (CN, RU, KP, IR, SY)
  - **Tor/VPN/Malicious IPs**: Detection of anonymized access methods
  - **Geographic Baseline Deviation**: Unusual locations compared to user history
- **Industry Context**: Common in APT campaigns, credential theft, and account compromise
- **Technical Implementation**:
  - **GeoIP Integration**: Real-time IP geolocation with risk scoring
  - **Distance Calculations**: Haversine formula for travel distance computation
  - **Time Analysis**: Sequential login timing for impossible travel detection
  - **Risk Country Database**: Configurable high-risk country list
  - **VPN/Tor Detection**: Network-level anonymization identification

#### Off-Hours Access Rule
- **ID**: `off_hours_access_detection`
- **Category**: Temporal/Behavioral
- **Severity**: Medium
- **Windows Event IDs**: 4624, 4625, 4648
- **Detection Logic**:
  - **Business Hours Violations**: Logins outside 7 AM - 7 PM window
  - **Weekend Access**: Any authentication on Saturday/Sunday
  - **Holiday Access**: Authentication on configured holiday dates
  - **Privileged User Off-Hours**: Escalated severity for admin accounts
  - **Late Night Activity**: Access between 10 PM - 5 AM
  - **Consistent Off-Hours Patterns**: Multiple days of off-hours access
- **Industry Context**: Common in insider threats, compromised credentials, and unauthorized access
- **Technical Implementation**:
  - **Configurable Business Hours**: Customizable time windows per environment
  - **Holiday Calendar Integration**: Support for configurable holiday dates
  - **User Profile Integration**: Cross-reference with normal login patterns
  - **Geographic Context**: Off-hours access from unusual locations
  - **Pattern Analysis**: Frequency and consistency of off-hours activity
- **Cross-References**: Works with `geographic_anomaly`, `privileged_access`, enhances `logon_pattern`

#### Privileged Access Rule
- **ID**: `privileged_access_monitoring`
- **Category**: Privilege
- **Severity**: High
- **Windows Event IDs**: 4624, 4672, 4673, 4674, 4720
- **Detection Logic**:
  - **Excessive Privileged Logins**: >5 logins per hour by privileged users
  - **Multi-System Access**: Privileged user accessing >3 different systems
  - **Service Account Interactive Logins**: Service accounts performing interactive authentication
  - **Suspicious Source Access**: Privileged access from Tor/VPN/malicious IPs
  - **Dormant Account Reactivation**: Privileged accounts active after >30 days of inactivity
- **Industry Context**: Privileged accounts are primary targets (Mimikatz, Pass-the-Hash, Golden Tickets)
- **Technical Implementation**:
  - **User Profile Integration**: Cross-reference with privileged user database
  - **Login Pattern Analysis**: Time intervals, frequency, and system access patterns
  - **System Classification**: Domain controllers, servers, critical infrastructure identification
  - **Source IP Intelligence**: Integration with GeoIP and threat intelligence
  - **Historical Activity Tracking**: Dormant account detection and reactivation alerting

#### User Activity Rule
- **ID**: `user_activity`
- **Category**: Behavioral/Informational
- **Severity**: Info (Low)
- **Windows Event IDs**: 4624, 4625, 4672, 4720, 4722, 4724, 4732
- **Detection Logic**:
  - **Authentication Summaries**: User login success/failure ratios
  - **Pattern Analysis**: Most active hours, logon type distribution
  - **Multi-IP Usage**: Users authenticating from multiple source IPs
  - **Computer Access Patterns**: Systems accessed by each user
  - **Privileged Account Monitoring**: Special tracking for admin accounts
  - **Session Duration Analysis**: Login frequency and temporal patterns
- **Industry Context**: Provides baseline user behavior for anomaly detection
- **Technical Implementation**:
  - **User Profile Enrichment**: Cross-reference with Active Directory profiles
  - **Statistical Analysis**: Success rates, frequency analysis, pattern recognition
  - **Multi-Source Correlation**: IP addresses, computers, logon types
  - **Hourly Pattern Analysis**: 24-hour login distribution mapping
  - **Department-Level Insights**: Organizational behavior patterns
- **Cross-References**: Baseline for `geographic_anomaly`, `off_hours_access`, `privileged_access`, `logon_pattern`

#### Password Change Rule
- **ID**: `password_changes`
- **Category**: Authentication/Informational
- **Severity**: Info (Low)
- **Windows Event IDs**: 4624, 4625, 4723, 4724
- **Detection Logic**:
  - **Failed-to-Success Patterns**: Authentication failure followed by success within 1-60 minutes
  - **Rapid Activity After Failures**: Multiple authentication events within 10 minutes post-failure
  - **Privileged Account Changes**: Special monitoring for admin password activities
  - **Help Desk Correlation**: Potential password reset request patterns
  - **Unauthorized Changes**: Password modifications without proper authorization
- **Industry Context**: Critical for detecting credential compromise and password reset abuse
- **Technical Implementation**:
  - **Temporal Pattern Recognition**: Time-based correlation of failed/successful attempts
  - **Gap Analysis**: Configurable time windows for change detection (1-60 minutes)
  - **User Profile Integration**: Cross-reference with user profiles and department info
  - **Failure Reason Analysis**: Distinguishing between wrong password and other failures
  - **Multi-Source Correlation**: IP addresses, computers, and authentication methods
- **Cross-References**: Supports `brute_force_detection`, `privileged_access`, enhances `multiple_failure`

### Advanced Pattern Detection Rules

#### Multiple Failure Rule
- **ID**: `multiple_failures`
- **Category**: Authentication
- **Severity**: High
- **Windows Event IDs**: 4624, 4625, 4627, 4648, 4771, 4776
- **Detection Logic**:
  - **Failure Clustering**: ≥5 authentication failures within 30-minute windows
  - **Distributed Attacks**: Single IP targeting multiple users (≥3 users, ≥10 attempts)
  - **Attack Pattern Analysis**: Concentrated vs distributed, automated vs manual attacks
  - **Privileged Account Escalation**: Higher severity for admin account targeting
  - **Account Lockout Prevention**: Detection before lockout thresholds are reached
  - **Rapid-Fire Detection**: Sub-5-second intervals between attempts
- **Industry Context**: Foundation of credential-based attacks (brute force, password spraying, account enumeration)
- **Technical Implementation**:
  - **Time Window Clustering**: Rolling 30-minute windows for failure pattern detection
  - **Statistical Attack Classification**: Automated vs manual, concentrated vs distributed
  - **Failure Reason Correlation**: Wrong password vs invalid user vs other errors
  - **Source IP Intelligence**: Geographic and threat intelligence integration
  - **Privilege Escalation Detection**: Cross-reference with privileged user database
  - **Confidence Scoring**: Dynamic risk assessment based on attack characteristics
- **Cross-References**:
  - Foundation for `brute_force_detection` and `password_spray_pattern_detection`
  - Supports `password_spray_rule` for comprehensive spraying detection
  - Works with `privileged_access` for escalated account monitoring
  - Integrates with `host-user-alert-correlation` for multi-host failure analysis
  - Enhances `time-window-alert-correlation` for temporal attack pattern recognition

#### Logon Pattern Rule
- **ID**: `logon_patterns`
- **Category**: Behavioral
- **Severity**: High
- **Windows Event IDs**: 4624, 4625, 4648, 4672, 4778, 4779
- **Detection Logic**:
  - **Impossible Travel**: Travel requiring >800 km/h (impossible for commercial flight)
  - **Concurrent Sessions**: Multiple active logins from different IPs within 5 minutes
  - **Off-Hours Activity**: Authentication outside user's normal business hours
  - **Unusual RDP Usage**: Sudden Remote Desktop access when not normally used
  - **Privilege Escalation**: Non-privileged users accessing privileged systems
  - **Logon Type Anomalies**: Unexpected authentication methods (network vs interactive)
- **Industry Context**: Advanced persistent threats, account compromise, lateral movement detection
- **Technical Implementation**:
  - **Geographic Distance Calculation**: Haversine formula for impossible travel detection
  - **Session Tracking**: Concurrent session analysis with time-based windows
  - **User Profile Integration**: Cross-reference with normal login patterns and privileges
  - **Logon Type Analysis**: Interactive, Network, RemoteInteractive, Batch authentication
  - **Temporal Pattern Recognition**: Hour-by-hour activity pattern analysis
  - **Privilege Boundary Checking**: Access control validation against user permissions
- **Cross-References**: Enhances `geographic_anomaly`, `off_hours_access`, `privileged_access`, `host_user_alert_correlation`

#### NTLMAuthentication Rule
- **ID**: `ntlm_authentication_failures`
- **Category**: Authentication
- **Severity**: High
- **Windows Event IDs**: 4776 (NTLM authentication), 4624, 4625
- **Detection Logic**:
  - **NTLM Enumeration**: ≥30 unique users failing NTLM authentication from single source
  - **Invalid Username Patterns**: STATUS_NO_SUCH_USER (0xc0000064) vs wrong passwords
  - **High-Volume Scanning**: >50 unique users suggesting automated scanning
  - **NTLM Relay Opportunities**: NTLM authentication usage patterns
  - **Downgrade Attacks**: Forced NTLM usage instead of Kerberos
- **Industry Context**: NTLM vulnerabilities exploited in relay attacks (NTLM Relay, PetitPotam)
- **Technical Implementation**:
  - **NTLM Failure Analysis**: Specific NTLM authentication failure codes and reasons
  - **Source IP Correlation**: Grouping attacks by originating workstation/IP
  - **Time Window Analysis**: 5-minute windows for attack clustering
  - **Attack Pattern Classification**: Invalid users vs wrong passwords vs other errors
  - **Volume Threshold Analysis**: Distinguishing manual vs automated attacks
- **Cross-References**: Complements `kerberos_authentication_failures`, supports `multiple_failures`

#### Kerberos Authentication Rule
- **ID**: `kerberos_authentication_failures`
- **Category**: Authentication
- **Severity**: High
- **Windows Event IDs**: 4771 (Kerberos authentication), 4624, 4625
- **Detection Logic**:
  - **Kerberos Enumeration**: ≥30 unique users failing Kerberos authentication from single source
  - **Statistical Outlier Analysis**: Users with failure counts >3 standard deviations from mean
  - **Pre-Authentication Failures**: Kerberos pre-auth failure patterns (ASREP roasting)
  - **Ticket Granting Anomalies**: Unusual ticket requesting patterns
  - **Golden Ticket Indicators**: Suspicious ticket usage patterns
- **Industry Context**: Kerberos attacks including ASREP roasting, Kerberoasting, Golden/Silver ticket abuse
- **Technical Implementation**:
  - **Statistical Pattern Recognition**: Standard deviation analysis for outlier detection
  - **Kerberos Failure Analysis**: Specific Kerberos authentication failure codes
  - **Source IP Correlation**: Grouping attacks by originating IP address
  - **Time Window Analysis**: 5-minute windows for attack pattern clustering
  - **Confidence Scoring**: Dynamic risk assessment based on statistical significance
  - **Attack Pattern Classification**: Pre-auth vs post-auth failures, enumeration vs brute force
- **Cross-References**: Complements `ntlm_authentication_failures`, supports `multiple_failures`, `password_spray_pattern`

#### Password Spray Rule
- **ID**: `password_spray_detection`
- **Category**: Authentication
- **Severity**: Critical
- **Windows Event IDs**: 4624, 4625, 4648, 4771
- **Detection Logic**:
  - **Multi-User Targeting**: Single IP attempting ≥10 users within 30 minutes
  - **Low Success Rate**: ≤25% success rate (characteristic of password spraying)
  - **Total Attempt Threshold**: ≥20 authentication attempts from single source
  - **Privileged Account Compromise**: Detection when privileged accounts are successfully accessed
  - **Distributed Pattern Recognition**: One password tried against multiple accounts
- **Industry Context**: More stealthy than brute force, evades account lockout policies
- **Technical Implementation**:
  - **Source IP Analysis**: Grouping attempts by originating IP address
  - **Success/Failure Ratio**: Statistical analysis of authentication outcomes
  - **User Targeting Patterns**: Detection of systematic user enumeration
  - **Time Window Analysis**: 30-minute rolling window for attack identification
  - **Privilege Escalation Detection**: Cross-reference with privileged user database

#### RDP Activity Rule
- **ID**: `rdp-activity`
- **Category**: Network
- **Severity**: Medium
- **Windows Event IDs**: 4624 (LogonType=10), 4625, 4778, 4779
- **Detection Logic**:
  - **Multiple RDP Sessions**: User with concurrent RDP connections
  - **Unusual RDP Sources**: RDP access from unexpected geographic locations
  - **High-Frequency RDP**: Rapid RDP connection/disconnection patterns
  - **Privileged RDP Access**: Domain/Enterprise admins using RDP
  - **RDP from Suspicious IPs**: RDP connections from Tor/VPN/malicious sources
- **Industry Context**: RDP is primary lateral movement technique (BlueKeep, RDP-based attacks)
- **Technical Implementation**:
  - **Logon Type Analysis**: Identification of RemoteInteractive logins (LogonType=10)
  - **Session Tracking**: RDP session establishment and termination monitoring
  - **Source IP Correlation**: Geographic and threat intelligence analysis
  - **Concurrent Session Detection**: Multiple active RDP sessions per user
  - **Administrative RDP Monitoring**: Elevated privilege RDP access patterns

#### SMB Enumeration Rule
- **ID**: `smb_enumeration_detection`
- **Category**: Network
- **Severity**: High
- **Windows Event IDs**: 4625 (Failed Logon), 4776 (NTLM Authentication), 4624 (Successful Logon), 5140 (Network Share Access), 5145 (Detailed Network Share Access)
- **Detection Logic**:
  - **User Enumeration via NTLM**: ≥20 unique usernames attempted from single source with >70% invalid users
  - **Null Session Enumeration**: ≥3 anonymous network logins from single source indicating share enumeration
  - **Sequential Username Patterns**: Detection of automated user discovery (user1, user2, user3, etc.)
  - **Rapid SMB Authentication Attempts**: ≥5 attempts per minute indicating automated enumeration tools
  - **Invalid User Targeting**: High ratio of STATUS_NO_SUCH_USER (0xc0000064) errors
- **Industry Context**: SMB enumeration is a common reconnaissance technique used by attackers to map network resources, discover valid usernames, and identify accessible shares. Often precedes credential-based attacks and lateral movement.
- **Technical Implementation**:
  - **NTLM Failure Analysis**: Specific NTLM authentication failure codes and patterns
  - **Source IP Correlation**: Groups enumeration attempts by originating IP address
  - **Sequential Pattern Detection**: Regex-based detection of automated username progressions
  - **Frequency Analysis**: Time-based attack velocity calculation
  - **Null Session Monitoring**: Detection of "ANONYMOUS LOGON" authentication events
  - **IP Intelligence Integration**: Geographic and threat intelligence for source risk scoring
- **Cross-References**: Works with `ntlm_authentication_failures`, `anonymous_account_monitoring`, `ip_alert_pattern`

#### Explicit Credentials Rule
- **ID**: `explicit_credentials_monitoring`
- **Category**: Authentication/Privilege
- **Severity**: High
- **Windows Event IDs**: 4648 (Explicit credential usage)
- **Detection Logic**:
  - **RunAs Credential Usage**: Single user accessing ≥30 different accounts
  - **Privileged Account Targeting**: Explicit credentials used against admin accounts
  - **Computer-Based Patterns**: Unusual explicit credential activity on specific computers
  - **High-Volume Targeting**: >50 unique accounts accessed with explicit credentials
- **Industry Context**: Common in lateral movement attacks, credential theft, and privilege escalation
- **Technical Implementation**:
  - **Event ID 4648 Monitoring**: Specific Windows event for explicit credential usage
  - **Caller-Target Correlation**: Tracks which user is using credentials to access which accounts
  - **Time Window Analysis**: 5-minute windows for grouping related credential usage
  - **Privilege Escalation Detection**: Cross-reference with privileged user database
- **Cross-References**: Complements `privileged_access`, `host_user_alert_correlation`, supports `lateral_movement_detection`

#### Local Admin Attacks Rule
- **ID**: `local_admin_credential_stuffing`
- **Category**: Authentication/Privilege
- **Severity**: Critical
- **Windows Event IDs**: 4624, 4625, 4648, 4771, 4776
- **Detection Logic**:
  - **Credential Stuffing**: Single IP targeting administrator accounts across ≥30 computers
  - **Local Admin Enumeration**: Attempts against common admin usernames (administrator, admin, root, sa)
  - **Successful Compromise**: Successful logins after failed attempts to admin accounts
  - **Rapid Admin Attempts**: >10 admin authentication attempts within 5 minutes
  - **Widespread Targeting**: Admin attacks across multiple computers from single source
- **Industry Context**: Primary attack vector for lateral movement (Pass-the-Hash, credential stuffing)
- **Technical Implementation**:
  - **Admin Username Pattern Matching**: Detection of common administrator account names
  - **Source IP Correlation**: Groups attacks by originating IP address
  - **Success/Failure Analysis**: Identifies credential compromise indicators
  - **Computer Target Mapping**: Tracks which systems are targeted in admin attacks
  - **Velocity Analysis**: Rapid-fire attempt detection for automated attacks
- **Cross-References**: Supports `multiple_failures`, `explicit_credentials`, enhances `lateral_movement_detection`

#### Anonymous Account Rule
- **ID**: `anonymous_account_monitoring`
- **Category**: Authentication/Security
- **Severity**: Medium
- **Windows Event IDs**: 4624, 4625, 4742 (Account changes)
- **Detection Logic**:
  - **Null Session Detection**: "ANONYMOUS LOGON" successful authentications (≥5 events)
  - **Suspicious Source Analysis**: Anonymous access from Tor/VPN/malicious IPs
  - **Reconnaissance Patterns**: Multiple logon types from anonymous sessions
  - **Anonymous Account Modifications**: Changes to anonymous/null accounts (Event ID 4742)
  - **Geographic Risk Assessment**: Anonymous access from high-risk countries
- **Industry Context**: Null sessions used for reconnaissance, SMB enumeration, and network mapping
- **Technical Implementation**:
  - **Null Session Monitoring**: Detection of "ANONYMOUS LOGON" authentication events
  - **GeoIP Intelligence Integration**: Risk assessment of anonymous access sources
  - **Logon Type Analysis**: Network vs Interactive anonymous access patterns
  - **Account Change Tracking**: Anonymous account modification detection
  - **Risk-Based Scoring**: Geographic and source-based risk evaluation
- **Cross-References**: Supports `ip_alert_pattern`, `geographic_anomaly`, enhances `network_reconnaissance_detection`

### Correlation Rules

#### Host-User Alert Correlation Rule
- **ID**: `host-user-alert-correlation`
- **Category**: Correlation
- **Severity**: Critical
- **Windows Event IDs**: 4624, 4625, 4672, 4720, 4722, 4724, 4725, 4732, 4733, 4740, 4771
- **Detection Logic**:
  - **Authentication Failure Sequences**: ≥5 auth failures followed by suspicious activity
  - **Brute Force Success**: Successful login after multiple failures
  - **Privilege Escalation Operations**: Special privileges, account modifications, group changes
  - **Rapid Activity Bursts**: ≥10 events within 10-minute window
  - **Account Lifecycle Events**: Account creation, enabling, disabling, password resets
- **Industry Context**: Advanced Persistent Threat (APT) behavior, account compromise detection
- **Technical Implementation**:
  - **User-Host Correlation**: Analysis of user activity on specific systems
  - **Risk Scoring Algorithm**: Weighted risk factors (0.0-1.0 confidence scoring)
  - **Time Window Analysis**: Event clustering and temporal pattern recognition
  - **Privilege Operation Tracking**: Special privilege assignments and account modifications
  - **Evidence Aggregation**: Comprehensive compromise indicator collection

#### IP Alert Pattern Rule
- **ID**: `ip-alert-pattern-correlation`
- **Category**: Network/Correlation
- **Severity**: High
- **Windows Event IDs**: 4624, 4625, 4672, 4732, 4740
- **Detection Logic**:
  - **Multi-User Targeting**: Single IP attempting ≥3 different users
  - **Multi-Host Scanning**: Single IP accessing ≥2 different computers
  - **High Failure Rates**: >80% authentication failure rate from single IP
  - **Brute Force Success**: Successful logins after ≥10 failures from same IP
  - **Privilege Escalation**: Multiple privilege changes from single IP
  - **Account Lockout Patterns**: Multiple lockouts triggered from single IP
  - **Rapid-Fire Attempts**: ≥5 authentication events within 1 second
- **Industry Context**: Coordinated attacks, scanning campaigns, command and control servers
- **Technical Implementation**:
  - **IP-Based Event Grouping**: All authentication events grouped by source IP
  - **Risk Scoring Algorithm**: Weighted scoring based on attack patterns and diversity
  - **Pattern Recognition**: Multi-dimensional analysis (users, hosts, success/failure rates)
  - **Time Window Analysis**: 2-hour rolling windows for pattern correlation
  - **Geographic Intelligence**: Optional integration with GeoIP for location-based context
- **Cross-References**: Works with `geographic_anomaly`, `multiple_failures`, supports `coordinated_attack_detection`

#### Time Window Correlation Rule
- **ID**: `time-window-alert-correlation`
- **Category**: Temporal/Correlation
- **Severity**: High
- **Windows Event IDs**: All authentication events (4624, 4625, 4672, 4732, etc.)
- **Detection Logic**:
  - **Rapid Alert Sequences**: ≥4 alerts from user@computer within 15-minute windows
  - **Time Gap Analysis**: Events occurring within 5-minute intervals
  - **Pattern Recognition**: Failed→successful logons, privilege escalations, high failure rates
  - **Sequence Risk Scoring**: Weighted scoring based on sequence characteristics
  - **High-Volume Bursts**: ≥10 events within short time windows
- **Industry Context**: Malware activity, automated attacks, compromised credential usage
- **Technical Implementation**:
  - **Sequence Detection Algorithm**: Groups events by user@computer combinations
  - **Time Window Clustering**: 15-minute windows with 5-minute maximum gaps
  - **Pattern Analysis**: Event type diversity, failure/success ratios, privilege operations
  - **Risk Scoring**: Duration, sequence length, pattern complexity weighted scoring
  - **Evidence Aggregation**: Comprehensive sequence metadata and timeline analysis
- **Cross-References**: Enhances all other rules by detecting rapid alert sequences, works with `host_user_alert_correlation`, `ip_alert_pattern`

#### Privilege Escalation Correlation Rule
- **ID**: `privilege-escalation-correlation`
- **Category**: Privilege
- **Severity**: Critical
- **Windows Event IDs**: 4672, 4720, 4722, 4724, 4732, 4733, 4756, 4757
- **Detection Logic**:
  - **Privilege Escalation Chains**: ≥3 privilege-related events within 45 minutes
  - **Suspicious Sequences**: Account creation + privilege assignment, password reset + group membership
  - **Rapid Privilege Changes**: Multiple privilege modifications within 30-minute window
  - **Multi-Host Escalation**: Privilege changes across ≥2 different systems
  - **Administrative Account Creation**: New privileged account creation patterns
- **Industry Context**: Advanced privilege escalation attacks (Mimikatz, Pass-the-Hash, Golden Ticket abuse)
- **Technical Implementation**:
  - **Event Sequence Analysis**: Temporal correlation of privilege-related events
  - **Risk Scoring Algorithm**: Weighted scoring based on privilege operation types
  - **Escalation Path Tracking**: Detailed sequence of privilege modifications
  - **Multi-Host Correlation**: Cross-system privilege escalation detection
  - **Suspicious Pattern Recognition**: Predefined attack pattern sequences

### Service Account Rules

#### Service Account Anomaly Rule
- **ID**: `service_account_anomaly_detection`
- **Category**: Authentication/Behavioral
- **Severity**: High
- **Windows Event IDs**: 4624, 4625, 4672, 4732, 4756
- **Detection Logic**:
  - **Authentication Failures**: ≥10 failed logins (service accounts rarely fail)
  - **Geographic Spread**: Authentication from ≥3 different locations
  - **Unusual Hours**: Service account activity outside expected patterns
  - **Concurrent Sessions**: ≥5 concurrent sessions (service account abuse)
  - **Account Age**: Service accounts >365 days without review
  - **Privilege Escalation**: Privilege changes on service accounts
- **Industry Context**: Service accounts are prime targets for persistence (Mimikatz, Golden Ticket attacks)
- **Technical Implementation**:
  - **Service Account Identification**: Cross-reference with user profile database
  - **Pattern Baseline**: Historical behavior analysis for service accounts
  - **Geographic Consistency**: Location-based authentication validation
  - **Session Management**: Concurrent session tracking and limits
  - **Privilege Monitoring**: Special privilege assignment detection

#### Service Account Lifecycle Rule
- **ID**: `service_account_lifecycle_detection`
- **Category**: Authentication/Security
- **Severity**: Medium
- **Windows Event IDs**: 4720, 4722, 4724, 4732, 4733, 4756, 4757
- **Detection Logic**:
  - **Password Aging**: Service accounts with passwords >365 days old
  - **Account Inactivity**: Service accounts inactive >90 days
  - **Unmanaged Accounts**: Regular user accounts used as service accounts (>50% threshold)
  - **Type Distribution Analysis**: Poor service account classification patterns
  - **High Authentication Volume**: Service accounts with >1000 auth events in time window
- **Industry Context**: Service accounts often have weak password policies and poor lifecycle management
- **Technical Implementation**:
  - **User Profile Integration**: Cross-references with Active Directory user profiles
  - **Password Age Calculation**: Tracks passwordLastSet vs current date
  - **Activity Monitoring**: Monitors lastLogonDate for inactivity detection
  - **Account Classification**: Analyzes serviceAccountType and indicators
  - **Volume Analysis**: Authentication event frequency analysis
- **Cross-References**: Enhances `service_account_anomaly_detection`, `service_account_correlation`

#### Service Account Correlation Rule
- **ID**: `service_account_correlation`
- **Category**: Correlation
- **Severity**: Critical
- **Windows Event IDs**: 4624, 4625, 4672, 4720, 4732, 4740, 4756, 4771
- **Detection Logic**:
  - **Coordinated Attacks**: ≥3 service accounts failing authentication from same IPs within time window
  - **Privilege Escalation Cascades**: Multiple service accounts receiving privileges simultaneously
  - **Geographic Spread**: ≥3 service accounts authenticating from unusual geographic locations
  - **Lockout Patterns**: Multiple service accounts experiencing lockouts in short time window
- **Industry Context**: Service accounts are high-value targets for lateral movement and persistence
- **Technical Implementation**:
  - **Time Window Analysis**: Groups events into configurable time windows for correlation
  - **Multi-Account Pattern Recognition**: Detects coordinated attacks across service accounts
  - **Geographic Intelligence Integration**: Cross-references with GeoIP data
  - **Risk Scoring Algorithm**: Weighted scoring based on attack patterns and severity
  - **Evidence Aggregation**: Comprehensive evidence collection for forensic analysis
- **Cross-References**: Works with `geographic_anomaly`, `privilege_escalation_correlation`, `host_user_alert_correlation`

### Enhanced Detection Rules

#### Password Spray Pattern Rule
- **ID**: `password_spray_pattern_detection`
- **Category**: Authentication
- **Severity**: Critical
- **Windows Event IDs**: 4624, 4625, 4627, 4648, 4771, 4776
- **Detection Logic**:
  - **AD Attributes Method**: ≥5 users with simultaneous authentication failures using user profile data
  - **Temporal Pattern Method**: Even distribution of failures across users in short time windows
  - **IP-Based Method**: Single source attempting authentication against multiple users at high frequency
  - **Statistical Analysis**: Coefficient of variation analysis for failure distribution patterns
  - **Volume Thresholds**: >10 attempts/minute with ≥5 target users
- **Industry Context**: More sophisticated than brute force, bypasses account lockout policies, common in APT campaigns
- **Technical Implementation**:
  - **Multi-Method Detection**: Three complementary detection algorithms working together
  - **AD Integration**: Leverages badPasswordCount and lastBadPasswordAttempt attributes
  - **Statistical Pattern Recognition**: Coefficient of variation analysis for even/uneven failure distributions
  - **Time Window Analysis**: Configurable time windows for simultaneous failure detection
  - **Source IP Correlation**: Groups attacks by originating IP address
  - **Confidence Scoring**: Dynamic confidence calculation based on multiple risk factors
- **Cross-References**:
  - Works with `brute_force_detection` for multi-stage attack detection
  - Works with `password_spray_rule` for complementary pattern recognition
  - Works with `geographic_anomaly` for location-based validation of spray sources
  - Integrates with `multiple_failures` for comprehensive failure pattern analysis
  - Supports `kerberos_authentication_failures` for cross-protocol attack correlation
  - Enhances `time-window-alert-correlation` for temporal spray pattern detection

---

## 🛡️ Active Directory Certificate Services (AD CS) Rules

### Locksmith Integration & Compatibility

ADTrapper's ESC rules are fully compatible with Jake Hildreth's **Locksmith** PowerShell tool for AD CS security assessment. Locksmith is a specialized tool designed to find and fix common misconfigurations in Active Directory Certificate Services.

#### **Locksmith Operational Modes**
- **Mode 0**: Identifies and outputs AD CS issues in console table format
- **Mode 1**: Identifies issues and provides possible fixes with example commands
- **Mode 2**: Outputs identified issues to `ADCSIssues.CSV` file
- **Mode 3**: Outputs issues and example fixes to `ADCSRemediation.CSV` file
- **Mode 4**: Interactive mode offering to fix all misconfigurations (use with caution)

#### **Locksmith Targeted Scanning**
- **Specific ESC Scanning**: `Locksmith.exe -Scans ESC1,ESC2,ESC8`
- **Comprehensive Assessment**: `Locksmith.exe -Scans All`
- **Custom Scan Sets**: `Locksmith.exe -Scans ESC1,ESC6,ESC9`
- **Interactive Selection**: `Locksmith.exe -Scans PromptMe` for user-guided selection
- **Risk-Based Reporting**: Recent updates include risk ratings (Informational to Critical)

#### **ADTrapper vs Locksmith: Feature Comparison**
| Feature | ADTrapper ESC Rules | Locksmith |
|---------|-------------------|-----------|
| **Real-time Detection** | ✅ Continuous monitoring | ❌ Point-in-time assessment |
| **Event Correlation** | ✅ Cross-system analysis | ❌ Static analysis |
| **Risk Scoring** | ✅ Dynamic confidence scoring | ✅ Risk ratings |
| **Historical Tracking** | ✅ Event timeline analysis | ❌ No historical data |
| **Integration** | ✅ SIEM, threat intelligence | ✅ CSV export, remediation scripts |
| **Automated Remediation** | ❌ Manual remediation required | ✅ Interactive remediation (Mode 4) |
| **Scalability** | ✅ Enterprise-scale analysis | ❌ Point-in-time limitations |
| **False Positive Reduction** | ✅ ML-based confidence scoring | ❌ Static rule-based |

#### **Complementary Usage Patterns**

**Recommended Approach:**
1. **Locksmith for Initial Assessment**: Use Locksmith for comprehensive point-in-time vulnerability assessment
2. **ADTrapper for Continuous Monitoring**: Deploy ADTrapper for real-time detection and alerting
3. **Combined Remediation**: Use Locksmith's Mode 4 for automated fixes, ADTrapper for validation
4. **Historical Analysis**: ADTrapper provides longitudinal visibility of AD CS security posture

**Integration Commands:**
```powershell
# Locksmith comprehensive scan
Invoke-Locksmith -Mode 2

# ADTrapper continuous monitoring (via API/SIEM integration)
# Real-time alerts and correlation with other security events

# Combined remediation workflow
Invoke-Locksmith -Mode 4 -Scans ESC1,ESC2  # Interactive fixes
# ADTrapper validates remediation effectiveness
```

### AD CS Attack Chain Detection

ADTrapper provides comprehensive coverage of the complete **AD CS attack chain**:

#### **Reconnaissance Phase**
- Certificate template enumeration via `anonymous_account` rule
- Template permission analysis via `esc4_access_control_detection`
- Certificate Authority discovery via `certificate_authentication_correlation`

#### **Initial Access Phase**
- Enrollment agent compromise via `esc3_enrollment_agent_detection`
- Vulnerable template exploitation via `esc1_vulnerable_template_detection`
- SubCA creation via `esc2_subca_template_detection`

#### **Privilege Escalation Phase**
- Certificate-based authentication via `certificate_authentication_correlation`
- Domain privilege escalation via `privileged_access`
- Cross-domain movement via `geographic_anomaly`

#### **Persistence Phase**
- Certificate renewal and persistence via `certificate_export`
- Enrollment agent reuse via `esc3_enrollment_agent_detection`
- Template modification persistence via `esc4_access_control_detection`

### ESC Attack Detection Rules

#### ESC1 Rule
- **ID**: `esc1_vulnerable_template_detection`
- **Category**: Certificate/Privilege Escalation
- **Severity**: Critical
- **Locksmith Equivalent**: `Find-ESC1` or `-Scans ESC1`
- **Windows Event IDs**: 4886, 4887, 4888, 53, 54
- **Detection Logic**:
  - **Enrollee-Supplied SANs**: Certificate templates allowing users to specify Subject Alternative Names without approval
  - **Client Authentication EKUs**: Templates with Client Authentication, PKINIT Client Auth, Smart Card Logon, or Any Purpose EKUs
  - **No Manager Approval**: Templates that don't require manager approval for certificate issuance
  - **Privileged User Targeting**: Certificate requests from privileged users using vulnerable templates
  - **Suspicious SAN Patterns**: Unusual domain names, admin accounts, or multiple subdomains in certificate requests
- **Industry Context**: Most common AD CS attack vector - allows domain user to request certificates for domain admin accounts
- **Technical Implementation**:
  - **Template Configuration Analysis**: Examines certificateNameFlags and enrollmentFlags for ENROLLEE_SUPPLIES_SUBJECT
  - **EKU Validation**: Checks extendedKeyUsage against dangerous client authentication EKUs
  - **SAN Pattern Analysis**: Detects suspicious patterns in Subject Alternative Names
  - **Risk Scoring**: Combines template vulnerabilities with user privilege levels
  - **Event Pattern Recognition**: Identifies certificate requests from vulnerable templates
- **Cross-References**: Complements `privileged_access`, `certificate_authentication_correlation`

#### ESC2 Rule
- **ID**: `esc2_subca_template_detection`
- **Category**: Certificate/Privilege Escalation
- **Severity**: Critical
- **Locksmith Equivalent**: `Find-ESC2` or `-Scans ESC2`
- **Windows Event IDs**: 4886, 4887, 4888, 53, 54
- **Detection Logic**:
  - **Any Purpose EKU**: Certificate templates with "Any Purpose" (2.5.29.37.0) Extended Key Usage
  - **No EKU Specified**: Templates without explicit Extended Key Usage restrictions
  - **SubCA Capabilities**: Templates that can create SubCA certificates (OCSP Signing, Time Stamping, etc.)
  - **No Manager Approval**: Templates allowing certificate issuance without approval
  - **Privileged User Requests**: Certificate requests from privileged users using vulnerable templates
  - **Large Group Accessibility**: Templates accessible by large user groups (Domain Users, Authenticated Users)
- **Industry Context**: Enables creation of subordinate Certificate Authorities, allowing attackers to issue their own certificates
- **Technical Implementation**:
  - **EKU Analysis**: Examines extendedKeyUsage for Any Purpose and SubCA-capable EKUs
  - **Template Permissions**: Analyzes which users/groups can request certificates from vulnerable templates
  - **Enrollment Flags**: Checks for manager approval and authorized signature requirements
  - **Certificate Pattern Recognition**: Identifies certificates issued with SubCA capabilities
  - **Risk Assessment**: Combines template vulnerabilities with accessibility and usage patterns
- **Cross-References**: Works with `certificate_authentication_correlation`, `adcs_attack_chain_correlation`

#### ESC3 Rule
- **ID**: `esc3_enrollment_agent_detection`
- **Category**: Certificate/Privilege Escalation
- **Severity**: Critical
- **Locksmith Equivalent**: `Find-ESC3` or `-Scans ESC3`
- **Windows Event IDs**: 4886, 4887, 4888, 53, 54
- **Detection Logic**:
  - **ESC3 Condition 1**: Enrollment Agent certificates issued without manager approval or authorized signature
  - **ESC3 Condition 2**: Client authentication templates allowing enrollment via enrollment agents without approval
  - **Enrollment Agent EKU**: Templates with Certificate Request Agent (1.3.6.1.4.1.311.20.2.1) Extended Key Usage
  - **Agent Usage Tracking**: Monitors when enrollment agent certificates are used to request other certificates
  - **Privileged Agent Creation**: Enrollment agent certificates issued to privileged users
  - **Multiple Target Exploitation**: Enrollment agents used to request certificates for multiple different users
  - **Suspicious Usage Patterns**: Rapid certificate requests or unusual subject names through enrollment agents
- **Industry Context**: Allows attackers to obtain enrollment agent certificates and then request certificates for other users, enabling privilege escalation
- **Technical Implementation**:
  - **Enrollment Agent Detection**: Identifies certificates with Certificate Request Agent EKU
  - **Template Permission Analysis**: Checks which users can request enrollment agent certificates
  - **Approval Workflow Validation**: Verifies manager approval and authorized signature requirements
  - **Agent Usage Tracking**: Monitors enrollment agent certificates used for requesting other certificates
  - **Cross-Template Correlation**: Links enrollment agent certificates to certificates they were used to request
- **Cross-References**: Integrates with `certificate_authentication_correlation`, `privileged_access`

#### ESC4 Rule
- **ID**: `esc4_access_control_detection`
- **Category**: Certificate/Access Control
- **Severity**: Critical
- **Locksmith Equivalent**: `Find-ESC4` or `-Scans ESC4`
- **Windows Event IDs**: 4898, 4899, 4900, 5136, 5137, 5141
- **Detection Logic**:
  - **Dangerous Permissions**: GenericAll, WriteDacl, WriteOwner, WriteProperty, GenericWrite on certificate templates
  - **PKI Object Permissions**: Dangerous permissions on Certificate Authorities and PKI containers
  - **Unprivileged User Access**: Non-administrative users with dangerous permissions on certificate objects
  - **Large Group Permissions**: Permissions granted to large groups (Domain Users, Authenticated Users, Everyone)
  - **Permission Changes**: Detection of permission modifications on certificate templates and PKI objects
  - **Current Permission Analysis**: Analysis of existing permissions on certificate templates
  - **Critical PKI Object Access**: Dangerous permissions on NTAuthCertificates, Root CA objects
- **Industry Context**: Weak access controls on certificate templates and PKI objects allow attackers to modify templates and escalate privileges
- **Technical Implementation**:
  - **Permission Analysis**: Examines ACEs (Access Control Entries) for dangerous permission combinations
  - **Principal Classification**: Identifies privileged vs unprivileged users and groups
  - **Inheritance Analysis**: Checks for permission inheritance patterns
  - **Object Type Classification**: Distinguishes between certificate templates, PKI objects, and CA objects
  - **Risk Scoring Algorithm**: Weighted risk assessment based on permission types and principal privileges
  - **Historical Change Tracking**: Monitors permission changes over time
- **Cross-References**: Works with `explicit_credentials`, `privileged_access`, `host_user_alert_correlation`

#### ESC6 Rule
- **ID**: `esc6_editf_flag_detection`
- **Category**: Certificate/Privilege Escalation
- **Severity**: High
- **Locksmith Equivalent**: `Find-ESC6` or `-Scans ESC6`
- **Windows Event IDs**: 4886, 4887, 4888, 53, 54
- **Detection Logic**:
  - **EDITF_ATTRIBUTESUBJECTALTNAME2 Flag**: CA configuration allowing arbitrary Subject Alternative Names
  - **Suspicious SAN Patterns**: Unusual domain names, admin accounts, multiple subdomains in certificates
  - **Cross-Template Vulnerabilities**: ESC1/ESC9 template vulnerabilities combined with dangerous CA flags
  - **Arbitrary SAN Exploitation**: Certificates with suspicious or unauthorized SAN values
  - **CA Configuration Analysis**: Registry flag analysis for vulnerable CA settings
  - **Certificate Request Pattern Analysis**: Statistical analysis of SAN usage patterns
- **Industry Context**: Allows attackers to request certificates for privileged accounts (domain admins) without approval. Common in targeted attacks where attackers compromise low-privilege accounts and escalate via certificate requests.
- **Technical Implementation**:
  - **CA Edit Flags Analysis**: Examination of EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) flag in CA registry
  - **SAN Pattern Detection**: Suspicious domain and username patterns in certificate requests using regex matching
  - **Cross-Vulnerability Correlation**: Integration with ESC1 and ESC9 template analysis for comprehensive risk assessment
  - **Risk Scoring Algorithm**: Dynamic scoring combining CA configuration risk with template vulnerability severity
  - **Certificate Request Correlation**: Links suspicious SAN requests to originating user accounts and IP addresses
  - **Historical Pattern Analysis**: Tracks SAN usage patterns over time to identify baseline deviations
- **Cross-References**:
  - Works with `esc1_vulnerable_template_detection` for template vulnerability correlation
  - Works with `esc9_weak_certificate_binding` for certificate security extension analysis
  - Integrates with `certificate_authentication_correlation` for certificate usage monitoring
  - Supports `geographic_anomaly` for suspicious SAN request source analysis

#### ESC7 Rule
- **ID**: `esc7_nonstandard_pki_admins`
- **Category**: Certificate/Access Control
- **Severity**: High
- **Locksmith Equivalent**: `Find-ESC7` or `-Scans ESC7`
- **Windows Event IDs**: 4886, 4887, 4888, 4898, 4899, 5136, 5137
- **Detection Logic**:
  - **Non-Standard PKI Administrators**: Users outside Domain/Enterprise Admins with CA control
  - **Certificate Manager Rights**: Users with certificate issuance and management permissions
  - **Administrative Certificate Operations**: Non-standard admins performing CA operations
  - **Privileged Certificate Issuance**: Non-standard admins issuing certificates to privileged accounts
  - **Dangerous Permission Combinations**: Users with GenericAll or WriteDacl on PKI objects
  - **CA Security Descriptor Analysis**: ACL analysis for CA and template objects
  - **Group Membership Validation**: Verification against standard PKI admin groups
- **Industry Context**: Violates principle of least privilege, increases attack surface for PKI compromise. Common in environments where PKI administration is delegated without proper oversight, creating persistence opportunities for attackers.
- **Technical Implementation**:
  - **Standard Admin Validation**: Cross-reference against Domain/Enterprise Admins and Cert Publishers groups
  - **Permission Analysis**: Deep inspection of CA and template access control entries (ACEs)
  - **Certificate Operation Tracking**: Monitoring administrative certificate activities by user
  - **Privilege Escalation Detection**: Pattern recognition for non-standard admin privilege operations
  - **Risk Assessment Algorithm**: Weighted scoring based on permission types, user privilege levels, and operation frequency
  - **Historical Activity Analysis**: Tracking administrative actions over time for anomaly detection
- **Cross-References**:
  - Works with `esc4_access_control_detection` for comprehensive PKI permission analysis
  - Works with `privileged_access` for privileged user activity correlation
  - Works with `explicit_credentials` for credential usage monitoring
  - Integrates with `host_user_alert_correlation` for multi-host administrative activity analysis

#### ESC8 Rule
- **ID**: `esc8_http_enrollment_detection`
- **Category**: Certificate/Network Security
- **Severity**: Medium
- **Locksmith Equivalent**: `Find-ESC8` or `-Scans ESC8`
- **Windows Event IDs**: 4886, 4887, 4888, 53, 54
- **Detection Logic**:
  - **HTTP Certificate Enrollment**: CA web enrollment endpoints using HTTP instead of HTTPS
  - **HTTP Enrollment Attempts**: Certificate requests made via unencrypted HTTP channels
  - **NTLM Authentication Usage**: NTLM authentication with HTTP enrollment (vulnerable to relay)
  - **Suspicious Source Enrollment**: HTTP certificate requests from VPN/Tor/malicious IPs
  - **Extended Protection for Authentication**: Missing EPA configuration on web enrollment
  - **Certificate Request Interception**: Man-in-the-middle attacks on enrollment traffic
  - **Relay Attack Patterns**: NTLM relay exploitation for certificate theft
- **Industry Context**: HTTP enrollment vulnerable to interception, relay attacks, and credential theft. Enables attackers to capture certificate requests and issue certificates for other users, commonly exploited in NTLM relay attacks like PetitPotam.
- **Technical Implementation**:
  - **Web Enrollment Configuration Analysis**: Deep inspection of CA web enrollment settings and HTTPS enforcement flags
  - **Protocol Detection Algorithm**: Identification of HTTP vs HTTPS enrollment attempts using URL and protocol analysis
  - **NTLM Usage Detection**: Analysis of authentication methods used with web enrollment via event correlation
  - **Source IP Intelligence Integration**: Geographic and threat intelligence feeds for enrollment source analysis
  - **Enrollment Pattern Analysis Engine**: Statistical analysis of enrollment behavior patterns and anomalies
  - **Certificate Request Correlation**: Linking enrollment attempts to successful certificate issuances
- **Cross-References**:
  - Works with `geographic_anomaly` for suspicious enrollment source geographic analysis
  - Works with `ip_alert_pattern` for IP-based enrollment attack pattern correlation
  - Enhances `certificate_authentication_correlation` for certificate usage monitoring
  - Integrates with `ntlm_authentication_failures` for NTLM relay attack detection
  - Supports `multiple_failures` for comprehensive enrollment failure analysis
  - Works with `time-window-alert-correlation` for temporal enrollment attack patterns

#### ESC9 Rule
- **ID**: `esc9_weak_certificate_binding`
- **Category**: Certificate/Privilege Escalation
- **Severity**: High
- **Locksmith Equivalent**: `Find-ESC9` or `-Scans ESC9`
- **Windows Event IDs**: 4887, 54 (Certificate issued)
- **Detection Logic**:
  - **Weak Certificate Binding**: Templates with DISABLE_NTDS_CA_SECURITY_EXT flag (0x80000) set
  - **Missing Security Extension**: Certificates issued without szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2)
  - **Client Authentication Certificates**: Weak certificates that can be used for domain authentication
  - **Privileged User Certificates**: Weak certificates issued to privileged domain accounts
  - **Template Accessibility**: Templates accessible by large user groups without manager approval
  - **Certificate Extension Validation**: Real-time verification of certificate security extensions
  - **Enrollment Flag Analysis**: Deep inspection of template enrollment configuration flags
- **Industry Context**: Certificates without strong binding can be used to impersonate privileged accounts and bypass security controls. Critical vulnerability exploited in advanced persistent threats where attackers need to maintain privileged access without detection.
- **Technical Implementation**:
  - **Certificate Extension Analysis Engine**: Automated detection of missing szOID_NTDS_CA_SECURITY_EXT extension in issued certificates
  - **Template Enrollment Flags Inspection**: Deep analysis of DISABLE_NTDS_CA_SECURITY_EXT flag (0x80000) in template configuration
  - **Extended Key Usage Validation**: Identification of certificates with client authentication capabilities (EKU 1.3.6.1.5.5.7.3.2)
  - **Certificate Binding Verification**: Cross-reference with Active Directory security extensions and domain controller validation
  - **Privilege Escalation Risk Assessment Algorithm**: Dynamic scoring based on certificate capabilities, user privileges, and access patterns
  - **Certificate Lifecycle Tracking**: Monitoring certificate issuance, renewal, and revocation with security extension validation
- **Cross-References**:
  - Works with `esc1_vulnerable_template_detection` for comprehensive template vulnerability assessment
  - Works with `certificate_authentication_correlation` for certificate usage and authentication monitoring
  - Works with `privileged_access` for privileged user activity correlation
  - Integrates with `esc6_editf_flag_detection` for CA-level security configuration analysis

#### ESC11 Rule
- **ID**: `esc11_unencrypted_requests_detection`
- **Category**: Certificate/Network Security
- **Severity**: Medium
- **Locksmith Equivalent**: `Find-ESC11` or `-Scans ESC11`
- **Windows Event IDs**: 4886, 4887, 4888, 53, 54
- **Detection Logic**:
  - **Unencrypted Certificate Requests**: RPC certificate requests without IF_ENFORCEENCRYPTICERTREQUEST flag
  - **NTLM Authentication Usage**: NTLM-based certificate requests vulnerable to relay attacks
  - **RPC Interface Vulnerabilities**: CA RPC endpoints without encryption enforcement
  - **Suspicious Source Requests**: HTTP certificate requests from VPN/Tor/malicious IPs
  - **Certificate Request Interception**: Man-in-the-middle attacks on RPC certificate enrollment
  - **Authentication Relay Exploitation**: NTLM relay patterns for certificate theft
  - **Protocol Analysis**: Detection of unencrypted vs encrypted certificate communication
- **Industry Context**: Unencrypted certificate requests are vulnerable to NTLM relay attacks, allowing attackers to obtain certificates for other users. Critical in environments using legacy RPC certificate enrollment without proper network encryption.
- **Technical Implementation**:
  - **CA Interface Flag Analysis Engine**: Deep inspection of IF_ENFORCEENCRYPTICERTREQUEST (0x00000200) flag in CA configuration
  - **Protocol Detection Algorithm**: Automated identification of RPC vs HTTPS enrollment methods using protocol analysis
  - **NTLM Usage Detection System**: Advanced analysis of authentication methods used with certificate requests via event correlation
  - **Source IP Intelligence Integration**: Comprehensive geographic and threat intelligence feeds for enrollment source analysis
  - **Certificate Request Pattern Analysis**: Statistical analysis of enrollment behavior patterns and anomalies
  - **Authentication Method Correlation**: Linking certificate requests to authentication mechanisms and vulnerabilities
- **Cross-References**:
  - Works with `esc8_http_enrollment_detection` for comprehensive enrollment security analysis
  - Works with `geographic_anomaly` for suspicious enrollment source geographic validation
  - Works with `ip_alert_pattern` for IP-based enrollment attack pattern correlation
  - Integrates with `ntlm_authentication_failures` for NTLM relay attack detection

#### ESC13 Rule
- **ID**: `esc13_group_linked_templates`
- **Category**: Certificate/Privilege Escalation
- **Severity**: High
- **Locksmith Equivalent**: `Find-ESC13` or `-Scans ESC13`
- **Windows Event IDs**: 4887, 54 (Certificate issued)
- **Detection Logic**:
  - **Group-Linked Certificate Templates**: Templates linked to groups via msDS-OIDToGroupLink attribute
  - **Automatic Certificate Issuance**: Templates that issue certificates to group members without approval
  - **Privileged Group Links**: Templates linked to Domain Admins, Enterprise Admins, or other privileged groups
  - **OID-Based Group Membership**: Certificate issuance policies using group-linked Object Identifiers
  - **Certificate Auto-Enrollment**: Group Policy-based automatic certificate deployment
  - **Group Membership Validation**: Real-time verification of group membership for certificate issuance
  - **Privilege Escalation Through Groups**: Attackers compromising group members to gain privileged certificates
- **Industry Context**: Group-linked templates allow attackers to compromise a group member and automatically receive privileged certificates. Enables persistence and privilege escalation by targeting group membership rather than individual users.
- **Technical Implementation**:
  - **OID Group Link Analysis Engine**: Deep examination of msDS-OIDToGroupLink attributes in certificate templates
  - **Issuance Policy Validation System**: Comprehensive analysis of certificate issuance policies for group-based authorization
  - **Group Membership Correlation Algorithm**: Advanced cross-reference between certificate recipients and linked groups
  - **Privilege Escalation Risk Assessment Engine**: Dynamic scoring based on linked group privileges, template accessibility, and group size
  - **Certificate Auto-Enrollment Detection**: Group Policy-based automatic certificate deployment monitoring
  - **Group Membership Change Tracking**: Monitoring group membership changes that affect certificate eligibility
- **Cross-References**:
  - Works with `esc1_vulnerable_template_detection` for template vulnerability assessment
  - Works with `privileged_access` for privileged group activity monitoring
  - Works with `certificate_authentication_correlation` for certificate usage tracking
  - Integrates with `sharpHound-group-membership-analysis` for comprehensive group analysis

#### ESC15 Rule
- **ID**: `esc15_schema_v1_detection`
- **Category**: Certificate/Privilege Escalation
- **Severity**: Critical
- **Locksmith Equivalent**: `Find-ESC15` or `-Scans ESC15`
- **Windows Event IDs**: 4887, 54 (Certificate issued)
- **Detection Logic**:
  - **Schema Version 1 Templates**: Certificate templates using Schema V1 (vulnerable to CVE-2024-49019)
  - **EKUwu Vulnerability**: Templates that allow arbitrary Extended Key Usage specification
  - **Arbitrary EKU Exploitation**: Certificates issued with suspicious or privileged EKUs
  - **Client Authentication Abuse**: Templates allowing client authentication EKU for privilege escalation
  - **Schema Version Validation**: Real-time detection of vulnerable template schema versions
  - **EKU Manipulation Detection**: Identification of certificates with unauthorized EKUs
  - **Privilege Escalation via EKU**: Attackers requesting certificates with privileged EKUs
- **Industry Context**: CVE-2024-49019 (EKUwu) allows attackers to request certificates with arbitrary EKUs, enabling privilege escalation through authentication bypasses. Critical vulnerability affecting Windows Certificate Services.
- **Technical Implementation**:
  - **Schema Version Analysis Engine**: Automated detection of Schema V1 certificate templates using schemaVersion field
  - **EKU Specification Validation System**: Deep analysis of templates allowing arbitrary EKU specification (missing EKU restrictions)
  - **Certificate Extension Analysis Engine**: Detection of certificates with suspicious or privileged EKUs using OID matching
  - **Privilege Escalation Risk Assessment Algorithm**: Dynamic scoring based on EKU capabilities, certificate usage patterns, and user privileges
  - **Certificate Request Pattern Analysis**: Statistical analysis of EKU usage patterns and anomalies
  - **CVE-2024-49019 Correlation**: Specific detection patterns for EKUwu exploitation techniques
- **Cross-References**:
  - Works with `esc1_vulnerable_template_detection` for comprehensive template vulnerability assessment
  - Works with `certificate_authentication_correlation` for certificate usage and authentication monitoring
  - Works with `privileged_access` for privileged user activity correlation
  - Integrates with `esc9_weak_certificate_binding` for certificate security extension analysis

#### ESC16 Rule
- **ID**: `esc16_ca_security_extension_disabled`
- **Category**: Certificate/Access Control
- **Severity**: Medium
- **Locksmith Equivalent**: `Find-ESC16` or `-Scans ESC16`
- **Windows Event IDs**: 4887, 54 (Certificate issued)
- **Detection Logic**:
  - **CA Security Extension Disabled**: Certificate Authorities with szOID_NTDS_CA_SECURITY_EXT disabled
  - **Weak Certificate Binding**: Certificates issued without strong binding controls
  - **CA-Level Configuration Vulnerabilities**: CA security settings that disable certificate validation
  - **Certificate Issuance Without Security Extensions**: Certificates issued by vulnerable CAs
  - **CA Security Flag Analysis**: Registry and configuration flag validation
  - **Certificate Extension Verification**: Real-time validation of certificate security extensions
  - **CA Configuration Auditing**: Comprehensive CA security settings assessment
- **Industry Context**: When CA security extensions are disabled, certificates can be issued without proper binding controls, allowing privilege escalation attacks. Affects the entire Certificate Authority infrastructure security.
- **Technical Implementation**:
  - **CA Security Flag Analysis Engine**: Deep examination of CA security configuration for disabled extensions
  - **Certificate Extension Validation System**: Automated detection of certificates missing szOID_NTDS_CA_SECURITY_EXT
  - **CA Configuration Assessment Engine**: Comprehensive analysis of CA security and interface flags
  - **Certificate Binding Verification Algorithm**: Cross-reference with Active Directory security extensions and domain controller validation
  - **Certificate Issuance Monitoring**: Real-time tracking of certificates issued by vulnerable CAs
  - **CA Security Audit Engine**: Automated auditing of CA configuration against security baselines
- **Cross-References**:
  - Works with `esc9_weak_certificate_binding` for certificate-level security extension analysis
  - Works with `certificate_authentication_correlation` for certificate usage monitoring
  - Works with `privileged_access` for privileged user activity correlation
  - Integrates with `esc4_access_control_detection` for comprehensive PKI access control analysis

### AD CS Security Assessment (Locksmith Compatible)

ADTrapper's AD CS rules are designed to complement Jake Hildreth's Locksmith PowerShell module, providing automated detection of certificate-based attack vectors.

#### **Additional ESC Vulnerabilities Detected by ADTrapper**

Beyond the core ESC1-ESC16 rules, ADTrapper provides comprehensive coverage of additional AD CS attack vectors:

**ESC6 - AD CS Backup Extraction**
- **Detection**: Unauthorized access to CA private keys through backup files
- **Risk**: Complete compromise of Certificate Authority infrastructure
- **Locksmith Integration**: Backup permission analysis and secure storage validation

**ESC7 - Vulnerable Certificate Authority Access Control**
- **Detection**: Weak access controls on Certificate Authority operations
- **Risk**: Direct manipulation of CA settings and certificate issuance
- **Locksmith Integration**: CA permission analysis and access control remediation

**ESC8 - NTLM Relay to AD CS HTTP Endpoints**
- **Detection**: NTLM authentication relay attacks on HTTP certificate enrollment
- **Risk**: Certificate theft and privilege escalation through relay attacks
- **Locksmith Integration**: HTTP endpoint security assessment and NTLM protection

**ESC9 - No Security Extension**
- **Detection**: Certificate templates lacking proper EKU specifications
- **Risk**: Certificates usable for any purpose, bypassing intended restrictions
- **Locksmith Integration**: EKU configuration validation and template hardening

**ESC10 - Rogue Certificate Authority**
- **Detection**: Unauthorized Certificate Authorities added to enterprise NTAuth store
- **Risk**: Trusted certificate issuance by rogue CAs compromising entire PKI infrastructure
- **Locksmith Integration**: CA trust validation and rogue CA detection using `Find-ESC10`
- **Technical Implementation**: NTAuthCertificates object analysis, CA certificate validation, trust relationship verification
- **Industry Context**: Rogue CAs can issue trusted certificates for any purpose, enabling complete PKI compromise and man-in-the-middle attacks

#### **Locksmith Integration Best Practices**

**Recommended Assessment Workflow:**
1. **Locksmith Point-in-Time Assessment**: Use Locksmith for comprehensive vulnerability discovery
2. **ADTrapper Continuous Monitoring**: Deploy ADTrapper for real-time detection and alerting
3. **Integrated Remediation**: Combine Locksmith's Mode 4 remediation with ADTrapper validation
4. **Historical Analysis**: ADTrapper provides longitudinal visibility of AD CS security posture

**PowerShell Integration Commands:**
```powershell
# Comprehensive Locksmith assessment
Invoke-Locksmith -Mode 2 -Scans All

# ADTrapper complementary monitoring
# Real-time alerts for new ESC vulnerabilities

# Combined remediation approach
Invoke-Locksmith -Mode 4 -Scans ESC1,ESC6,ESC11
# ADTrapper validates remediation effectiveness
```

#### **Enterprise AD CS Security Architecture**

ADTrapper's ESC rules implement a defense-in-depth approach to AD CS security:

**Prevention Layer:**
- Certificate template hardening (ESC1-ESC5, ESC9, ESC13, ESC15)
- CA configuration security (ESC6, ESC7, ESC16)
- Enrollment process protection (ESC8, ESC11)

**Detection Layer:**
- Real-time vulnerability monitoring
- Certificate issuance anomaly detection
- Authentication pattern analysis

**Response Layer:**
- Automated alerting and incident response
- Certificate revocation coordination
- Remediation validation and verification

#### ESC Vulnerability Detection Rules

##### ESC1 Analysis (Locksmith Compatible)
- **ID**: `esc1`
- **Category**: Certificate
- **Severity**: Critical
- **Locksmith Equivalent**: `Find-ESC1`
- **What it detects**:
  - Certificate templates allowing "Any Purpose" client authentication
  - Templates with overly broad certificate usages
  - Authentication certificates without proper restrictions
  - ESC1 privilege escalation opportunities

##### ESC2 Analysis (Locksmith Compatible)
- **ID**: `esc2`
- **Category**: Certificate
- **Severity**: Critical
- **Locksmith Equivalent**: `Find-ESC2`
- **What it detects**:
  - Dangerous Enhanced Key Usage (EKU) combinations
  - Authentication certificates with minimal validation
  - Certificate templates vulnerable to abuse
  - ESC2 attack vector identification

##### ESC3 Analysis (Locksmith Compatible)
- **ID**: `esc3`
- **Category**: Certificate
- **Severity**: High
- **Locksmith Equivalent**: `Find-ESC3`
- **What it detects**:
  - Certificate templates with overly permissive enrollment rights
  - Any domain user can enroll certificates
  - Weak enrollment authorization controls
  - Unauthorized certificate request capabilities

##### ESC4 Analysis (Locksmith Compatible)
- **ID**: `esc4`
- **Category**: Certificate
- **Severity**: High
- **Locksmith Equivalent**: `Find-ESC4`
- **What it detects**:
  - Certificate templates vulnerable to manager approval bypass
  - Weak approval workflow configurations
  - Certificate request authorization weaknesses
  - Approval process circumvention opportunities

##### ESC6 Analysis (Locksmith Compatible)
- **ID**: `esc6`
- **Category**: Certificate
- **Severity**: High
- **Locksmith Equivalent**: `Find-ESC6`
- **What it detects**:
  - EDITF_ATTRIBUTESUBJECTALTNAME2 flag vulnerabilities
  - Subject Alternative Name (SAN) manipulation attacks
  - Certificate template schema weaknesses
  - ESC6 exploitation vectors

##### ESC7 Analysis (Locksmith Compatible)
- **ID**: `esc7`
- **Category**: Certificate
- **Severity**: Medium
- **Locksmith Equivalent**: `Find-ESC7`
- **What it detects**:
  - Vulnerable HTTP certificate enrollment services
  - Certificate requests via HTTP without authentication
  - Web-based certificate enrollment weaknesses
  - HTTP certificate request vulnerabilities

##### ESC8 Analysis (Locksmith Compatible)
- **ID**: `esc8`
- **Category**: Certificate
- **Severity**: Medium
- **Locksmith Equivalent**: `Find-ESC8`
- **What it detects**:
  - NTLM relay vulnerabilities in certificate enrollment
  - Certificate request susceptible to NTLM relay attacks
  - Authentication relay attack opportunities
  - NTLM-based certificate request weaknesses

##### ESC9 Analysis (Locksmith Compatible)
- **ID**: `esc9`
- **Category**: Certificate
- **Severity**: Medium
- **Locksmith Equivalent**: `Find-ESC9`
- **What it detects**:
  - Certificate templates without No Security Extension
  - Missing security extension configurations
  - Certificate template security flag issues
  - ESC9 bypass opportunities

##### ESC11 Analysis (Locksmith Compatible)
- **ID**: `esc11`
- **Category**: Certificate
- **Severity**: High
- **Locksmith Equivalent**: `Find-ESC11`
- **What it detects**:
  - Certificate request agent template vulnerabilities
  - Agent certificate template misconfigurations
  - Certificate request agent security weaknesses
  - Agent-based certificate enrollment issues

##### ESC13 Analysis (Locksmith Compatible)
- **ID**: `esc13`
- **Category**: Certificate
- **Severity**: High
- **Locksmith Equivalent**: `Find-ESC13`
- **What it detects**:
  - Certificate template V1 schema vulnerabilities
  - PKI object access control weaknesses
  - Schema-based certificate template attacks
  - V1 template security bypasses

##### ESC15 Analysis (Locksmith Compatible)
- **ID**: `esc15`
- **Category**: Certificate
- **Severity**: Critical
- **Locksmith Equivalent**: `Find-ESC15`
- **What it detects**:
  - Certificate template V2 schema vulnerabilities
  - msPKI-Enrollment-Flag weaknesses
  - Enhanced security flag bypass opportunities
  - V2 template schema attack vectors

#### AD CS Operational Security Rules

##### ADCS Auditing Rule
- **ID**: `adcs-auditing`
- **Category**: Certificate
- **Severity**: Low
- **What it detects**:
  - Certificate authority audit event logging
  - Certificate issuance and revocation tracking
  - Audit policy compliance verification
  - Certificate authority activity monitoring

##### Certificate Tool Detection Rule
- **ID**: `certificate-tool-detection`
- **Category**: Certificate
- **Severity**: Medium
- **What it detects**:
  - Certificate manipulation and request tools
  - Certificate management software usage
  - Tool-based certificate attacks and abuse
  - Certificate utility exploitation attempts

##### Certificate Export Rule
- **ID**: `certificate-export`
- **Category**: Certificate
- **Severity**: Medium
- **What it detects**:
  - Certificate and private key export activities
  - Certificate theft and exfiltration attempts
  - Private key compromise indicators
  - Certificate export security violations

##### CA Backup Rule
- **ID**: `ca-backup`
- **Category**: Certificate/Infrastructure Security
- **Severity**: High
- **Windows Event IDs**: 4885, 4886, 4888 (Backup/Restore events)
- **Detection Logic**:
  - **Certificate Authority Database Backup**: Monitoring CA database backup operations and access
  - **CA Private Key Backup Access**: Unauthorized access to CA private key backup files
  - **Certificate Authority Compromise Indicators**: Suspicious backup operations outside normal maintenance windows
  - **Backup Security Policy Violations**: Backup operations by unauthorized users or from suspicious sources
  - **CA Key Export Detection**: Detection of CA private key export operations
  - **Backup File Access Patterns**: Monitoring access to CA backup files and directories
- **Industry Context**: CA private keys are the crown jewels of PKI infrastructure. Unauthorized backup access can lead to complete PKI compromise and issuance of fraudulent certificates.
- **Technical Implementation**:
  - **Backup Operation Monitoring**: Real-time tracking of CA database backup and restore operations
  - **Private Key Access Detection**: Monitoring access to CA private key files and backup locations
  - **Authorization Validation**: Cross-reference backup operations against authorized maintenance schedules
  - **Source Authentication**: Validation of backup operation initiators and their authorization levels
  - **Backup Integrity Verification**: Detection of unauthorized modifications to backup files
- **Cross-References**:
  - Works with `privileged_access` for backup operation authorization validation
  - Works with `explicit_credentials` for backup credential usage monitoring
  - Integrates with `host_user_alert_correlation` for multi-system backup activity analysis

##### Certificate Authentication Correlation Rule
- **ID**: `certificate-authentication-correlation`
- **Category**: Certificate/Authentication
- **Severity**: High
- **Windows Event IDs**: 4624 (Success), 4625 (Failure), 4887 (Certificate issued), 4888 (Certificate revoked)
- **Detection Logic**:
  - **Certificate-Based Authentication Patterns**: Monitoring successful certificate authentications
  - **Certificate Compromise Indicators**: Authentication failures followed by suspicious certificate usage
  - **Authentication Correlation Analysis**: Linking certificate issuance to authentication events
  - **Certificate Trust Relationship Violations**: Certificates used outside authorized contexts
  - **Certificate Revocation Bypass**: Usage of revoked certificates for authentication
  - **Certificate Chain Validation**: Verification of certificate trust chains during authentication
  - **Multi-Certificate Usage**: Single user utilizing multiple certificates for authentication
- **Industry Context**: Certificate-based authentication is increasingly common in enterprise environments. Compromised certificates can be used for persistent access and privilege escalation.
- **Technical Implementation**:
  - **Certificate Authentication Monitoring**: Real-time tracking of certificate-based login events
  - **Certificate Validity Verification**: Cross-reference certificates against revocation lists (CRL/OCSP)
  - **Authentication Pattern Analysis**: Statistical analysis of certificate usage patterns
  - **Certificate Chain Validation**: Verification of certificate trust chains and issuer validity
  - **Revocation Status Checking**: Real-time validation against certificate revocation status
  - **Multi-Certificate Correlation**: Tracking multiple certificate usage by single users
- **Cross-References**:
  - Works with `privileged_access` for certificate-based privileged authentication monitoring
  - Works with `geographic_anomaly` for suspicious certificate authentication locations
  - Works with `certificate-export` for certificate theft and exfiltration detection
  - Integrates with `esc1_vulnerable_template_detection` for vulnerable certificate template correlation

##### ADCS Attack Chain Correlation Rule
- **ID**: `adcs-attack-chain-correlation`
- **Category**: Certificate/Attack Chain Analysis
- **Severity**: Critical
- **Windows Event IDs**: All AD CS events (4886, 4887, 4888, 53, 54, 4898, 4899)
- **Detection Logic**:
  - **Multi-Stage AD CS Exploitation Chains**: Detection of sequential AD CS attack patterns
  - **Certificate-Based Privilege Escalation Sequences**: Tracking privilege escalation through certificate abuse
  - **Complex Certificate Attack Patterns**: Advanced attack techniques combining multiple ESC vulnerabilities
  - **Advanced Persistent Threat Certificate Abuse**: Long-term certificate-based persistence mechanisms
  - **Certificate Template Manipulation**: Unauthorized template modifications and exploitations
  - **Certificate Authority Compromise**: Multi-step CA compromise and certificate issuance abuse
  - **Cross-Domain Certificate Attacks**: Certificate-based attacks spanning multiple domains
- **Industry Context**: AD CS attacks are increasingly sophisticated, combining multiple vulnerabilities for persistent access. Attack chains can span weeks or months with certificates providing legitimate-looking authentication.
- **Technical Implementation**:
  - **Attack Chain Pattern Recognition**: Machine learning-based detection of AD CS attack sequences
  - **Certificate Lifecycle Tracking**: End-to-end monitoring of certificate issuance, usage, and revocation
  - **Privilege Escalation Path Analysis**: Identification of certificate-based privilege escalation routes
  - **Cross-System Correlation**: Linking AD CS events across multiple systems and domains
  - **Temporal Attack Sequence Analysis**: Time-based analysis of attack progression and persistence
  - **Certificate Trust Chain Validation**: Verification of certificate trust relationships and anomalies
- **Cross-References**:
  - Works with all ESC rules (ESC1-ESC16) for comprehensive vulnerability correlation
  - Works with `certificate_authentication_correlation` for certificate usage tracking
  - Works with `privileged_access` for privilege escalation monitoring
  - Integrates with `sharpHound-kerberos-delegation` for delegation-based attack correlation

---

## 🔍 SharpHound Active Directory Analysis Rules

### 🏗️ Domain Infrastructure Security

#### SharpHound Domain Controller Analysis Rule
- **ID**: `sharpHound-domain-controller-analysis`
- **Category**: Security
- **Severity**: Critical
- **SharpHound Data Sources**: Computer objects, Domain Controller identification, LAPS properties
- **What it detects**:
  - **Domain controllers without LAPS protection** - Critical vulnerability allowing local admin password theft
  - **DCs with unconstrained Kerberos delegation** - Allows attackers to impersonate any domain user
  - **DCs with constrained delegation misconfigurations** - Potential for privilege escalation attacks
  - **DCs running outdated operating systems** - Missing security patches and features
  - **Single domain controller environments** - High availability and disaster recovery risks
  - **Dangerous DC permissions** - Overly permissive access to domain controller objects
- **Industry Context**: Aligns with BloodHound's domain controller analysis and Microsoft security baselines

#### SharpHound Domain Trust Analysis Rule
- **ID**: `sharpHound-domain-trust-analysis`
- **Category**: Privilege
- **Severity**: High
- **SharpHound Data Sources**: Domain trust objects, Trust properties, SID filtering settings
- **What it detects**:
  - **External domain trust relationships** - Potential attack vectors from untrusted domains
  - **Non-transitive trust configurations** - Limited attack path mapping but increased complexity
  - **SID filtering disabled** - Allows SID spoofing attacks and privilege escalation
  - **Outdated domain functional levels** - Missing modern security features and patches
  - **Trust relationship vulnerabilities** - Bidirectional trust exploitation opportunities
  - **Cross-forest trust misconfigurations** - Authentication bypass opportunities
- **Industry Context**: Critical for enterprise environments with complex trust architectures

### Privilege Escalation & Access Control

#### SharpHound Kerberos Delegation Analysis Rule
- **ID**: `sharpHound-kerberos-delegation`
- **Category**: Privilege
- **Severity**: High
- **SharpHound Data Sources**: User objects (AllowedToDelegate), Computer objects (AllowedToDelegate), Delegation properties
- **What it detects**:
  - **Unconstrained Kerberos delegation on user accounts** - Allows impersonation of any domain user (TrustedForDelegation)
  - **Unconstrained delegation on computer accounts** - Service accounts can be compromised for delegation attacks
  - **Excessive constrained delegation** - Too many services can delegate to user accounts (AllowedToDelegate)
  - **Administrator accounts with delegation** - Domain/Enterprise admins with delegation enabled
  - **Service accounts with unconstrained delegation** - Critical for Kerberoasting and delegation abuse
  - **TrustedForDelegation vs TrustedToAuthForDelegation** - Protocol transition vulnerabilities
- **Industry Context**: Delegation attacks are primary attack vector in AD environments (Pass-the-Ticket, Kerberoasting)

#### SharpHound User Rights Analysis Rule
- **ID**: `sharpHound-user-rights-analysis`
- **Category**: Privilege
- **Severity**: High
- **SharpHound Data Sources**: Computer ACEs, Local group memberships, Administrative permissions
- **What it detects**:
  - **Domain users with local admin rights on computers** - Direct admin access bypasses security controls
  - **Local Administrators group membership** - Users with full control over workstations/servers
  - **Remote Desktop Users with admin rights** - RDP access combined with admin privileges
  - **Service accounts with local admin rights** - Automated accounts with excessive permissions
  - **Domain groups with local admin rights** - Group-based admin access patterns
  - **Nested administrative permissions** - Indirect admin access through group membership
- **Industry Context**: Local admin rights enable lateral movement and privilege escalation attacks

#### SharpHound Group Membership Analysis Rule
- **ID**: `sharpHound-group-membership-analysis`
- **Category**: Privilege
- **Severity**: High
- **SharpHound Data Sources**: Group objects, MemberOf attributes, Group ACEs, Nested group relationships
- **What it detects**:
  - **Large privileged groups** - Domain Admins with hundreds of members (violates least privilege)
  - **Empty security groups** - Unused groups requiring cleanup or potential attack vectors
  - **Users with mixed privilege levels** - Accounts in both standard and privileged groups
  - **Built-in admin group direct memberships** - Users directly in Domain Admins (not via role groups)
  - **Nested group privilege accumulation** - Users gaining excessive rights through group nesting
  - **Cross-domain group memberships** - Users with privileges in multiple domains
- **Industry Context**: Group-based attacks are primary persistence and escalation mechanism in AD

#### SharpHound SID History Analysis Rule
- **ID**: `sharpHound-sid-history-analysis`
- **Category**: Privilege
- **Severity**: Medium
- **SharpHound Data Sources**: User objects (SIDHistory), Group objects, Domain SID relationships
- **What it detects**:
  - **Accounts with SID history entries** - Legacy SIDs from domain migrations or renames
  - **Privileged SIDs in history** - Former Domain Admin SIDs retained in account history
  - **Cross-domain SID history** - SIDs from different domains in user history
  - **SID filtering bypass opportunities** - Historical SIDs that bypass SID filtering
  - **Migration-related SID retention** - SIDs kept from AD migration scenarios
  - **Historical privilege preservation** - Old admin rights retained via SID history
- **Industry Context**: SID History enables privilege escalation and persistence across domain boundaries

### Account Security & Lifecycle

#### SharpHound Privileged Accounts Analysis Rule
- **ID**: `sharpHound-privileged-accounts`
- **Category**: Privilege
- **Severity**: High
- **What it detects**:
  - Accounts with non-expiring passwords
  - Accounts with pre-authentication disabled (ASREP roastable)
  - Service accounts with admin privileges
  - Password expiration policy violations
  - Privileged account security issues

#### SharpHound Service Account Analysis Rule
- **ID**: `sharpHound-service-account-analysis`
- **Category**: Privilege
- **Severity**: High
- **What it detects**:
  - Service accounts with Domain Admin privileges
  - Service accounts with SPNs (Kerberoasting risk)
  - Old service account passwords
  - Excessive service account privileges
  - Service account security misconfigurations

#### SharpHound Computer Account Analysis Rule
- **ID**: `sharpHound-computer-account-analysis`
- **Category**: Security/Asset Management
- **Severity**: Medium
- **SharpHound Data Sources**: Computer objects, Properties (enabled, pwdlastset, operatingsystem, whencreated)
- **What it detects**:
  - **Stale Computer Accounts**: Computers that haven't authenticated in extended periods
  - **Disabled Computer Accounts**: Disabled systems still in Active Directory
  - **Legacy Computer Accounts**: Pre-2000 accounts (vulnerable to legacy attacks)
  - **Outdated Operating Systems**: Systems running unsupported OS versions
  - **Computer Account Lifecycle Issues**: Accounts without proper maintenance
- **Industry Context**: Computer accounts represent significant attack surface in Active Directory. Stale accounts can be taken over, while outdated systems lack modern security features. Legacy accounts may be vulnerable to older attack techniques.
- **Technical Implementation**:
  - **Account Age Analysis**: Uses pwdlastset and whencreated for lifecycle assessment
  - **OS Version Detection**: Examines operatingsystem property for security baseline validation
  - **Account Status Validation**: Checks enabled/disabled status for proper asset management
  - **Staleness Calculation**: Configurable thresholds for inactive account detection
- **Cross-References**:
  - Works with `sharpHound-laps-analysis` for comprehensive computer security assessment
  - Works with `sharpHound-user-rights-analysis` for local admin privilege correlation
  - Integrates with `host-user-alert-correlation` for computer-based attack detection

### Certificate & Authentication Services

#### SharpHound Certificate Template Analysis Rule
- **ID**: `sharpHound-certificate-template-analysis`
- **Category**: Security/Certificate Services
- **Severity**: High
- **SharpHound Data Sources**: Certificate template objects, Enrollment permissions, Template properties, ESC vulnerabilities
- **Locksmith Integration**: Compatible with Jake Hildreth's Locksmith PowerShell module for AD CS auditing using `Find-ESC*` functions
- **What it detects**:
  - **ESC1: Vulnerable certificate templates** - Any Purpose client authentication without restrictions (enrolleeSuppliesSubject)
  - **ESC2: Dangerous EKU combinations** - Authentication certificates with minimal validation (Any Purpose EKU)
  - **ESC3: Overly permissive enrollment** - Any domain user can enroll certificates (no manager approval)
  - **ESC4: Vulnerable manager approval** - Certificate requests bypass approval workflow (weak ACLs)
  - **ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2** - Subject Alternative Name manipulation attacks (CA flag analysis)
  - **ESC7: Vulnerable HTTP enrollment** - Certificate requests via HTTP without authentication (web enrollment)
  - **ESC8: NTLM relay vulnerabilities** - Certificate enrollment susceptible to NTLM relay attacks
  - **ESC9: No Security Extension** - Certificate templates without proper security extensions (szOID_NTDS_CA_SECURITY_EXT)
  - **ESC11: Agent template vulnerabilities** - Certificate request agent template misconfigurations
  - **ESC13: Schema vulnerabilities** - PKI object access control weaknesses (group-linked templates)
  - **ESC15: V2 template schema issues** - Enhanced security flag bypass opportunities (Schema V1, EKUwu)
  - **ESC16: CA security extension disabled** - Certificate Authorities with weak binding controls
- **Industry Context**: AD CS attacks are primary escalation vector in modern enterprise environments. SharpHound's certificate template analysis provides comprehensive visibility into AD CS attack surfaces, enabling proactive hardening before exploitation occurs.
- **Technical Implementation**:
  - **Certificate Template ACL Analysis**: Deep inspection of template permissions and enrollment rights
  - **EKU Validation Engine**: Automated detection of dangerous Extended Key Usage combinations
  - **Schema Version Analysis**: Identification of vulnerable Schema V1 templates (CVE-2024-49019)
  - **Enrollment Flag Validation**: Analysis of enrollment requirements and approval workflows
  - **Cross-Template Correlation**: Linking certificate templates to user/group permissions
  - **Attack Path Integration**: Connecting certificate vulnerabilities to privilege escalation paths
- **Cross-References**:
  - Works with all ADTrapper ESC rules (ESC1-ESC16) for comprehensive AD CS security assessment
  - Works with `sharpHound-user-rights-analysis` for user permission correlation
  - Works with `sharpHound-group-membership-analysis` for group-based certificate access analysis
  - Integrates with `certificate_authentication_correlation` for certificate usage monitoring

#### SharpHound LAPS Analysis Rule
- **ID**: `sharpHound-laps-analysis`
- **Category**: Security/Local Admin Protection
- **Severity**: High
- **SharpHound Data Sources**: Computer objects (haslaps property), Domain Controller identification, LAPS password objects
- **What it detects**:
  - **Computers without LAPS protection** - Local admin passwords stored in clear text in AD (ms-Mcs-AdmPwd attribute)
  - **Servers missing LAPS (critical)** - Production servers vulnerable to lateral movement and credential theft
  - **Domain controllers without LAPS** - Most critical systems lacking password rotation (should always have LAPS)
  - **Workstations without LAPS** - End-user machines with static admin passwords enabling lateral movement
  - **LAPS coverage gaps** - Statistical analysis of LAPS deployment coverage across organizational units
  - **Legacy systems pre-LAPS** - Systems from before LAPS implementation requiring migration
  - **LAPS password age analysis** - Detection of stale LAPS passwords indicating rotation failures
  - **LAPS delegation issues** - Problems with LAPS password retrieval permissions
- **Industry Context**: LAPS (Local Administrator Password Solution) prevents Pass-the-Hash attacks and lateral movement via local admin credentials. Without LAPS, local admin passwords are stored in clear text in Active Directory, enabling attackers to move laterally across the network.
- **Technical Implementation**:
  - **LAPS Attribute Detection**: Analysis of ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime attributes
  - **Computer Object Classification**: Differentiation between servers, workstations, and domain controllers
  - **Organizational Unit Analysis**: LAPS coverage assessment by OU and department
  - **Password Age Validation**: Detection of expired or stale LAPS passwords
  - **Permission Analysis**: Validation of LAPS password retrieval rights and delegation
  - **Coverage Statistics**: Automated calculation of LAPS deployment percentages
- **Cross-References**:
  - Works with `sharpHound-user-rights-analysis` for local admin rights correlation
  - Works with `sharpHound-computer-account-analysis` for computer lifecycle management
  - Works with `sharpHound-domain-controller-analysis` for DC-specific security assessment
  - Integrates with `local_admin_credential_stuffing` for credential-based attack detection

### Group Policy & Configuration Management

#### SharpHound GPO Security Analysis Rule
- **ID**: `sharpHound-gpo-security-analysis`
- **Category**: Security/Configuration Management
- **Severity**: High
- **SharpHound Data Sources**: GPOs (Group Policy Objects), ACEs (Access Control Entries), Links, Properties
- **What it detects**:
  - **Unlinked GPOs**: GPOs not linked to any containers (orphaned policies) (↔ `flagUnlinkedGPOs` threshold)
  - **Overly Complex GPOs**: GPOs linked to >1000 objects (performance and management issues)
  - **Old GPOs**: GPOs not modified in 365+ days (stale policies) (↔ `flagOldGPOs` threshold)
  - **Dangerous GPO Permissions**: Write, Modify, Full Control, GenericAll rights on GPOs
  - **GPO Security Misconfigurations**: Weak access controls and delegation issues
- **Industry Context**: GPOs are critical for enterprise policy management but often become security risks through poor lifecycle management and excessive permissions. Unlinked and old GPOs create attack surface while dangerous permissions enable policy manipulation.
- **Technical Implementation**:
  - **GPO Link Analysis**: Examines Links array to identify unlinked GPOs
  - **Permission Analysis**: Deep inspection of ACEs for dangerous permission combinations
  - **Age Calculation**: Uses whenchanged property to detect stale GPOs
  - **Complexity Assessment**: Counts linked objects against configurable thresholds
  - **Risk Scoring**: Weighted assessment of GPO security posture
- **Cross-References**:
  - Works with `sharpHound-password-policy-analysis` for comprehensive policy assessment
  - Works with `host-user-alert-correlation` for GPO-based attack detection
  - Integrates with `sharpHound-domain-controller-analysis` for domain-wide policy impact

#### SharpHound Password Policy Analysis Rule
- **ID**: `sharpHound-password-policy-analysis`
- **Category**: Security/Password Management
- **Severity**: High
- **SharpHound Data Sources**: Users (Properties: pwdneverexpires, dontreqpreauth, pwdlastset, admincount, enabled)
- **What it detects**:
  - **Non-Expiring Passwords**: Accounts with pwdneverexpires=true (↔ `flagPasswordNeverExpires` threshold)
  - **ASREP-Roastable Accounts**: Users with dontreqpreauth=true (Kerberos pre-authentication disabled)
  - **Old Password Changes**: Passwords older than 90 days (↔ `maxPasswordAge` threshold)
  - **Inverted Privilege Policies**: Privileged accounts with weaker policies than non-privileged accounts
  - **Privileged Account Weaknesses**: Admin accounts with non-expiring passwords or disabled pre-auth
- **Industry Context**: Password policies are fundamental to Active Directory security. Weak configurations enable offline attacks like ASREP roasting and password cracking. Privileged accounts with non-expiring passwords are especially dangerous as they provide persistent access for attackers.
- **Technical Implementation**:
  - **Password Expiry Analysis**: Examines pwdneverexpires and pwdlastset properties
  - **Kerberos Pre-Authentication Check**: Validates dontreqpreauth flag for ASREP roasting vulnerability
  - **Privilege-Level Comparison**: Compares password policies between privileged and non-privileged accounts
  - **Age Calculation**: Uses pwdlastset timestamp to determine password age
  - **Account Status Validation**: Ensures analysis only includes enabled accounts
- **Cross-References**:
  - Works with `sharpHound-gpo-security-analysis` for policy enforcement verification
  - Works with `kerberos_authentication_failures` for ASREP roasting correlation
  - Works with `password_spray_pattern_detection` for password-related attack patterns
  - Integrates with `privileged_access` for privileged account password policy validation

---

## 🎯 Real-World Attack Scenario Detection

ADTrapper's rules are designed to detect specific attack techniques and security weaknesses commonly exploited in Active Directory environments:

### Primary Attack Vector Detection

#### **Kerberos-Based Attacks**
- **Golden Ticket Detection**: Identifies unconstrained delegation and service account vulnerabilities
- **Pass-the-Ticket**: Detects constrained delegation misconfigurations
- **Kerberoasting**: Flags service accounts with SPNs vulnerable to password cracking
- **ASREP Roasting**: Identifies accounts with disabled pre-authentication

#### **Privilege Escalation Paths**
- **Group Membership Attacks**: Large privileged groups, empty groups, nested permissions
- **SID History Exploitation**: Historical SIDs that bypass current security controls
- **Domain Trust Abuse**: External trusts, non-transitive relationships, SID filtering bypasses
- **Local Admin Exploitation**: Domain users with local admin rights on computers

#### **Lateral Movement Detection**
- **Local Administrator Analysis**: Computers with domain admin local rights
- **RDP Group Membership**: Remote access privilege analysis
- **Service Account Abuse**: Service accounts with excessive permissions
- **Computer Account Compromise**: Stale accounts, disabled systems, legacy OS

#### **Certificate-Based Attacks**
- **ESC1-ESC16 Vulnerabilities**: Complete AD CS attack surface coverage (↔ Locksmith `Find-ESC*` functions)
- **PetitPotam Detection**: NTLM relay vulnerabilities in certificate enrollment (↔ `esc8_http_enrollment_detection`, `esc11_unencrypted_requests_detection`)
- **Certifried Exploitation**: Certificate template schema weaknesses (↔ `esc15_schema_v1_detection` for CVE-2024-49019/EKUwu)
- **Certificate Theft**: Export and exfiltration detection (↔ `certificate-export`, `certificate_authentication_correlation`)
- **ESC6 SAN Manipulation**: Subject Alternative Name attacks (↔ `esc1_vulnerable_template_detection`, `esc6_editf_flag_detection`)
- **ESC13 Group-Linked Templates**: Automatic privilege escalation via group membership (↔ `esc13_group_linked_templates`, `sharpHound-group-membership-analysis`)

#### **Persistence Mechanisms**
- **Administrative Backdoors**: Hidden admin accounts and group memberships
- **GPO Persistence**: Malicious Group Policy modifications
- **Trust Relationship Abuse**: Cross-domain persistence via trusts
- **Certificate Persistence**: Long-lived authentication certificates

### Industry Threat Intelligence Integration

ADTrapper's rules are informed by:
- **MITRE ATT&CK Framework**: Enterprise techniques coverage (↔ `privilege-escalation-correlation` for T1068, T1078)
- **BloodHound Research**: Attack path analysis methodologies (↔ All SharpHound rules for attack path visualization)
- **Locksmith Findings**: AD CS security research (↔ All ESC rules for vulnerability detection)
- **Real-World Incident Response**: Common compromise patterns (↔ `host-user-alert-correlation` for incident analysis)
- **Microsoft Security Guidance**: Official hardening recommendations (↔ `sharpHound-laps-analysis` for LAPS compliance)

### Real-World Attack Scenario Detection

#### **SharpHound-Based Attack Chain Detection**

**GPO-Based Persistence Attack Chain:**
```
Initial Compromise → GPO Modification → Password Policy Weakening → ASREP Roasting
       ↓                        ↓                           ↓                    ↓
SharpHound GPO Analysis ← Password Policy Analysis ← Kerberos Auth Failures ← ASREP Roasting Alert
```

**Cross-Reference Details:**
- **Initial Compromise** ↔ **GPO Modification**: Attackers modify GPOs for persistence
- **Password Policy Weakening** ↔ **ASREP Roasting**: Disabled pre-auth creates ASREP roasting opportunities
- **SharpHound GPO Analysis** ↔ **Password Policy Analysis**: Detects policy weakening through GPO changes

#### **Certified Pre-Owned (CPO) Attack Chain**
```
Domain User Compromise → ESC1 Template Exploitation → Domain Admin Certificate → Full Domain Control
       ↓                              ↓                              ↓                    ↓
ESC1 Detection ← Certificate Request Monitoring ← Authentication Correlation ← Privilege Escalation Alert
```

**Cross-Reference Details:**
- **Domain User Compromise** ↔ **ESC1 Template Exploitation**: Standard user accounts can request admin certificates
- **Certificate Request Monitoring** ↔ **ESC1 Detection**: Vulnerable templates allow privilege escalation
- **Authentication Correlation** ↔ **Privilege Escalation Alert**: Certificate-based authentication abuse detection

#### **PetitPotam Attack Chain**
```
NTLM Relay Setup → ESC8 HTTP Enrollment → Certificate Theft → Domain Privilege Escalation
       ↓                     ↓                         ↓                    ↓
ESC8 Detection ← HTTP Protocol Analysis ← Certificate Export ← Authentication Correlation
```

**Cross-Reference Details:**
- **NTLM Relay Setup** ↔ **ESC8 HTTP Enrollment**: Unencrypted enrollment enables relay attacks
- **HTTP Protocol Analysis** ↔ **ESC8 Detection**: Protocol-level vulnerability identification
- **Certificate Export** ↔ **Authentication Correlation**: Exported certificates used for authentication

#### **EKUwu (CVE-2024-49019) Attack Chain**
```
Schema V1 Template → Arbitrary EKU Request → Privilege Certificate → Domain Admin Impersonation
       ↓                           ↓                         ↓                    ↓
ESC15 Detection ← EKU Manipulation Analysis ← Certificate Issuance ← Authentication Abuse
```

**Cross-Reference Details:**
- **Schema V1 Template** ↔ **ESC15 Detection**: Vulnerable template schema allows EKU manipulation
- **EKU Manipulation Analysis** ↔ **Arbitrary EKU Request**: Detection of unauthorized EKUs in certificates
- **Certificate Issuance** ↔ **Authentication Abuse**: Privilege certificates used for impersonation

## 📈 Rule Categories & Severity Distribution

### By Category
- **Authentication**: 15 rules (30%) - Login attacks, credential abuse, authentication bypasses
- **Privilege**: 13 rules (26%) - Escalation paths, delegation abuse, rights exploitation
- **Security**: 11 rules (22%) - System hardening, configuration weaknesses, compliance gaps
- **Network**: 5 rules (10%) - Geographic anomalies, IP-based attacks, C2 detection
- **Behavioral**: 4 rules (8%) - User pattern analysis, temporal anomalies, insider threats
- **Certificate**: 9 rules (18%) - AD CS vulnerabilities, PKI security, certificate abuse
- **Correlation**: 3 rules (6%) - Multi-stage attacks, attack chain analysis
- **Temporal**: 2 rules (4%) - Time-based patterns, scheduling anomalies

### By Severity Impact
- **Critical**: 8 rules (16%) - Immediate action required, severe security risks
- **High**: 25 rules (50%) - Significant security concerns requiring attention
- **Medium**: 12 rules (24%) - Moderate risks with hardening opportunities
- **Low**: 5 rules (10%) - Informational findings and optimization opportunities

### Detection Confidence Levels
- **High Confidence**: Rules based on definitive security violations
- **Medium Confidence**: Rules detecting suspicious patterns requiring investigation
- **Low Confidence**: Rules identifying potential optimization or hardening opportunities

## 🔬 Advanced Technical Capabilities

### Real-Time Analytics Engine

ADTrapper's analytics engine provides **enterprise-grade security analysis** with the following advanced capabilities:

#### **Multi-Vector Threat Detection**
- **Event Correlation**: Cross-system event correlation across Windows Event Logs, AD CS, and SharpHound data
- **Behavioral Analysis**: User and entity behavior analytics with baseline deviation detection
- **Temporal Pattern Recognition**: Time-based attack pattern identification and sequence analysis
- **Geographic Intelligence**: IP geolocation with threat intelligence integration

#### **Advanced Analytics Features**
- **Machine Learning Integration**: Pattern recognition and anomaly scoring algorithms
- **Risk Scoring Engine**: Dynamic risk assessment with confidence intervals
- **Evidence Aggregation**: Comprehensive evidence collection for forensic analysis
- **Alert Enrichment**: Contextual information and remediation recommendations
- **Historical Analysis**: Long-term trend analysis and baseline establishment

### Enterprise Security Integration

#### **Industry Standards Compliance**
- **MITRE ATT&CK Framework**: Complete technique coverage for enterprise environments (↔ `privilege-escalation-correlation` for T1068 Privilege Escalation)
- **NIST Cybersecurity Framework**: Security control mapping and compliance validation (↔ All authentication rules for IA-2 Identification & Authentication)
- **CIS Controls**: Critical security control implementation verification (↔ `sharpHound-laps-analysis` for CIS Control 4.4)
- **ISO 27001**: Information security management system alignment (↔ `certificate_authentication_correlation` for A.9 Access Control)
- **PCI DSS**: Payment card industry compliance (↔ `geographic_anomaly` for requirement 8.3)
- **HIPAA**: Healthcare compliance mapping (↔ `privileged_access` for access control requirements)
- **SOX**: Financial reporting compliance (↔ `host-user-alert-correlation` for audit trail requirements)

#### **Professional Tool Integration**
- **SharpHound Compatibility**: Full BloodHound data collection and analysis support
- **Locksmith Integration**: AD CS security assessment with Jake Hildreth's Locksmith
- **SIEM Integration**: Export capabilities for enterprise SIEM platforms
- **Threat Intelligence**: Real-time threat intelligence feed integration

### Performance & Scalability

#### **Enterprise-Grade Performance**
- **High-Volume Processing**: Handles millions of events per day
- **Distributed Architecture**: Scalable deployment across multiple nodes
- **Real-Time Analysis**: Sub-second threat detection and alerting
- **Resource Optimization**: Efficient memory usage and processing algorithms

#### **Operational Excellence**
- **Automated Tuning**: Self-optimizing rule thresholds based on environment
- **False Positive Reduction**: Advanced filtering and correlation techniques
- **Alert Prioritization**: Intelligent alert ranking and noise reduction
- **Performance Monitoring**: Built-in analytics performance metrics

---

## 🎯 Use Case Scenarios

### Enterprise Active Directory Security

#### **Red Team Assessment Support**
ADTrapper provides comprehensive visibility for red team operations:
- **Attack Path Mapping**: Complete attack path identification and visualization
- **Privilege Escalation Detection**: Real-time privilege escalation monitoring
- **Lateral Movement Tracking**: Cross-system movement detection and alerting
- **Persistence Mechanism Identification**: Advanced persistent threat detection

#### **Blue Team Operations**
Professional security operations support:
- **Incident Response**: Rapid threat identification and evidence collection
- **Threat Hunting**: Advanced threat hunting capabilities with pattern matching
- **Compliance Monitoring**: Continuous compliance validation and reporting
- **Security Posture Assessment**: Ongoing security health evaluation

#### **DevSecOps Integration**
Modern development security integration:
- **CI/CD Pipeline Security**: Automated security testing in development pipelines
- **Infrastructure as Code**: Security validation for IaC deployments
- **Container Security**: Kubernetes and container environment monitoring
- **Cloud Security**: Multi-cloud environment security assessment

### Specialized Security Scenarios

#### **High-Value Asset Protection**
Critical system protection capabilities:
- **Domain Controller Monitoring**: Specialized DC security analysis
- **Privileged Account Protection**: Advanced privileged access monitoring
- **Certificate Authority Security**: AD CS infrastructure protection
- **Service Account Security**: Automated account lifecycle management

#### **Advanced Threat Detection**
Sophisticated threat detection capabilities:
- **APT Detection**: Advanced persistent threat identification
- **Supply Chain Attacks**: Third-party and vendor risk assessment
- **Insider Threat Detection**: Internal threat identification and monitoring
- **State-Sponsored Attacks**: Nation-state level threat detection

---

## 🔗 Rule Cross-Reference Matrix

### Authentication Attack Detection Chain
```
Password Spray Pattern → Password Spray Rule → Brute Force Detection
       ↓                           ↓                    ↓
Geographic Anomaly ← Geographic Validation ← IP-based Correlation
       ↓                           ↓                    ↓
NTLM Authentication ← Kerberos Authentication ← Explicit Credentials
```

**Cross-Reference Details:**
- **Password Spray Pattern** ↔ **Kerberos Authentication**: Both detect statistical anomalies in authentication patterns
- **Brute Force Detection** ↔ **NTLM Authentication**: NTLM failures often indicate brute force attempts
- **Geographic Anomaly** ↔ **Explicit Credentials**: Suspicious credential usage from unusual locations
- **IP-based Correlation** ↔ **Multiple Failures**: Groups authentication failures by source for pattern analysis

### Privilege Escalation Detection Chain
```
Service Account Correlation → Privilege Escalation Correlation → Host-User Alert Correlation
       ↓                              ↓                              ↓
Service Account Lifecycle ← Service Account Anomaly ← Privileged Access Monitoring
       ↓                              ↓                              ↓
SharpHound SID History ← SharpHound Group Membership ← SharpHound User Rights
```

**Cross-Reference Details:**
- **Service Account Correlation** ↔ **SharpHound SID History**: Historical privilege retention in service accounts
- **Privilege Escalation Correlation** ↔ **SharpHound User Rights**: Local admin rights as privilege escalation vectors
- **Host-User Alert Correlation** ↔ **SharpHound Group Membership**: Group-based privilege accumulation patterns
- **Service Account Lifecycle** ↔ **Service Account Anomaly**: Account lifecycle violations and anomalous behavior
- **Privileged Access Monitoring** ↔ **Host-User Alert Correlation**: Multi-host privilege escalation detection

### Multi-Vector Attack Pattern Recognition
```
Windows Event Logs + AD CS + SharpHound Data
          ↓              ↓              ↓
   Correlation Rules → Risk Scoring → Alert Enrichment
          ↓              ↓              ↓
   Incident Response → Forensic Analysis → Threat Hunting
```

**Multi-Vector Integration Details:**
- **Windows Event Logs** ↔ **AD CS Rules**: Certificate authentication events correlate with Windows authentication logs
- **AD CS** ↔ **SharpHound Data**: Certificate templates map to user/group permissions and attack paths
- **SharpHound Data** ↔ **Windows Event Logs**: Active Directory changes correlate with authentication events
- **Correlation Rules** ↔ **Risk Scoring**: Multi-source evidence aggregation for confidence calculation
- **Alert Enrichment** ↔ **Incident Response**: Contextual information for rapid response decisions

### Certificate-Based Attack Chain
```
ESC1 Template Vuln → Certificate Request → Certificate Issuance → Authentication Abuse
       ↓                        ↓                        ↓                    ↓
ESC6 SAN Attack ← HTTP Enrollment ← NTLM Relay ← Certificate Export
```

**Cross-Reference Details:**
- **ESC1 Template Vuln** ↔ **Certificate Request**: Vulnerable templates enable arbitrary SAN requests
- **Certificate Issuance** ↔ **Authentication Abuse**: Issued certificates used for privilege escalation
- **ESC6 SAN Attack** ↔ **HTTP Enrollment**: CA configuration enables SAN manipulation attacks
- **NTLM Relay** ↔ **Certificate Export**: Exported certificates used in relay attacks
- **HTTP Enrollment** ↔ **ESC8 Detection**: Unencrypted enrollment vulnerable to interception

### Key Rule Relationships

#### **Primary Detection Rules**
- **Brute Force Detection** → Foundation for credential attack detection (↔ `multiple_failures`, `ntlm_authentication_failures`)
- **Password Spray Pattern** → Advanced credential attack detection with statistical analysis (↔ `kerberos_authentication_failures`, `geographic_anomaly`)
- **Geographic Anomaly** → Location-based attack validation and impossible travel detection (↔ `ip_alert_pattern`, `time-window-alert-correlation`)
- **Privileged Access** → Critical system access monitoring and alerting (↔ `host-user-alert-correlation`, `sharpHound-user-rights-analysis`)

#### **Correlation & Context Rules**
- **Host-User Alert Correlation** → Most sophisticated correlation rule with risk scoring (↔ `privilege-escalation-correlation`, `sharpHound-group-membership-analysis`)
- **Privilege Escalation Correlation** → Advanced privilege attack chain detection (↔ `sharpHound-sid-history-analysis`, `service-account-correlation`)
- **Service Account Correlation** → Service account attack pattern recognition (↔ `service-account-lifecycle`, `sharpHound-privileged-accounts`)
- **Time Window Correlation** → Temporal attack sequence analysis (↔ `ip-alert-pattern-correlation`, `multiple_failures`)

#### **Certificate Security Rules**
- **ESC1 Template Detection** → Certificate template vulnerability analysis (↔ `esc6_editf_flag_detection`, `certificate-authentication-correlation`)
- **ESC8 HTTP Enrollment** → Unencrypted enrollment vulnerability detection (↔ `esc11_unencrypted_requests_detection`, `geographic_anomaly`)
- **Certificate Authentication Correlation** → Certificate-based authentication monitoring (↔ `esc1_vulnerable_template_detection`, `privileged_access`)
- **ADCS Attack Chain Correlation** → Multi-stage certificate attack detection (↔ All ESC rules, `certificate-export`)

#### **SharpHound Integration Rules**
- **SharpHound LAPS Analysis** → Local admin password protection assessment (↔ `sharpHound-user-rights-analysis`, `sharpHound-computer-account-analysis`)
- **SharpHound Kerberos Delegation** → Delegation vulnerability detection (↔ `sharpHound-sid-history-analysis`, `sharpHound-group-membership-analysis`)
- **SharpHound Certificate Template Analysis** → AD CS security assessment (↔ All ESC rules, `certificate-authentication-correlation`)
- **SharpHound Domain Trust Analysis** → Trust relationship security evaluation (↔ `sharpHound-domain-controller-analysis`, `geographic_anomaly`)

#### **Specialized Detection Rules**
- **Service Account Lifecycle** → Service account management and compliance monitoring (↔ `service-account-anomaly`, `sharpHound-service-account-analysis`)
- **Service Account Anomaly** → Comprehensive service account behavioral analysis (↔ `service-account-lifecycle`, `privileged_access`)
- **Password Spray Pattern** → Multi-method password attack detection (AD attributes + temporal + IP-based) (↔ `brute_force_detection`, `kerberos_authentication_failures`)
- **Anonymous Account Monitoring** → Null session and reconnaissance detection (↔ `ip_alert_pattern`, `geographic_anomaly`)

### Integration Points with Industry Tools

#### **SharpHound Integration**
- **Domain Infrastructure**: `sharpHound-domain-controller-analysis`, `sharpHound-domain-trust-analysis` (↔ `geographic_anomaly` for cross-domain detection)
- **Privilege Escalation**: `sharpHound-kerberos-delegation`, `sharpHound-user-rights-analysis` (↔ `privilege-escalation-correlation` for attack path validation)
- **Account Security**: `sharpHound-privileged-accounts`, `sharpHound-sid-history` (↔ `service-account-lifecycle` for account management)
- **Certificate Services**: `sharpHound-certificate-template-analysis` (↔ All ESC rules for comprehensive AD CS assessment)
- **Group Policy**: `sharpHound-gpo-security-analysis` (↔ `sharpHound-password-policy-analysis` for security baseline validation)
- **Password Management**: `sharpHound-password-policy-analysis` (↔ `kerberos_authentication_failures` for ASREP roasting detection)
- **Local Admin Protection**: `sharpHound-laps-analysis` (↔ `local_admin_credential_stuffing` for credential-based attacks)

#### **Locksmith AD CS Integration**
- **ESC Vulnerability Detection**: ESC1-ESC16 rules map directly to Locksmith `Find-ESC*` functions
- **Certificate Template Analysis**: Automated AD CS security assessment (↔ `sharpHound-certificate-template-analysis` for comprehensive coverage)
- **PKI Security Monitoring**: Certificate authority and template security validation
- **Vulnerability Remediation**: Integration with Locksmith's Mode 4 for automated fixes
- **Assessment Workflows**: Point-in-time assessment complementing ADTrapper's continuous monitoring

#### **SIEM Integration Capabilities**
- **Splunk Integration**: CEF format export with custom mappings (↔ `ip_alert_pattern` for enhanced IP intelligence)
- **ELK Stack**: Elasticsearch integration with Kibana dashboards (↔ `time-window-alert-correlation` for temporal analysis)
- **Microsoft Sentinel**: Native Azure integration with security orchestration (↔ `host-user-alert-correlation` for incident response)
- **QRadar**: IBM QRadar integration with custom parsers (↔ `geographic_anomaly` for location-based alerting)

#### **Threat Intelligence Integration**
- **MITRE ATT&CK Mapping**: Direct correlation with ATT&CK framework techniques
- **CrowdStrike Threat Graph**: Integration with threat actor tracking
- **VirusTotal Integration**: File and URL reputation analysis
- **AbuseIPDB Integration**: Enhanced IP reputation scoring (↔ `geographic_anomaly` for malicious IP detection)

## 🔧 Configuration & Customization

### Threshold Configuration
Each rule includes configurable thresholds:
- Time windows for analysis
- Anomaly detection sensitivity
- Severity level adjustments
- Custom alerting parameters

### Rule Enablement
Rules can be individually enabled/disabled based on:
- Organizational security priorities
- Environment-specific requirements
- Performance considerations
- Compliance requirements

### Custom Rules
ADTrapper supports custom rule development for:
- Organization-specific security policies
- Unique threat detection requirements
- Specialized compliance monitoring
- Advanced correlation analysis

---
