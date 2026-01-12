// Core types for the analytics engine
export interface AuthEvent {
  id: string
  timestamp: Date
  eventId: string
  computerName?: string
  userName?: string
  domainName?: string
  sourceIp?: string
  sourcePort?: number
  logonType?: string
  status: 'Success' | 'Failed' | 'Logoff'
  failureReason?: string
  authenticationPackage?: string
  logonProcess?: string
  workstationName?: string
  rawData?: Record<string, any>
}

export interface Anomaly {
  id: string
  ruleId: string
  ruleName: string
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info'
  title: string
  description: string
  category: 'authentication' | 'network' | 'behavior' | 'privilege' | 'temporal' | 'informational' | 'security' | 'behavioral' | 'correlation'
  confidence: number // 0-100
  evidence: Record<string, any>
  affectedEntities?: Array<{
    type: 'user' | 'computer' | 'ip'
    id: string
    name: string
  }>
  timeWindow: {
    start: Date
    end: Date
  }
  metadata: Record<string, any>
  timestamp: Date
  detectedAt: Date
  recommendations?: string[]
  context?: Record<string, any>
}

export interface AnalyticsRule {
  id: string
  name: string
  description: string
  detailedDescription?: string | {
    overview: string
    detectionLogic: string
    falsePositives: string
    mitigation: string[]
    windowsEvents: string[]
    exampleQuery: string
    recommendedThresholds: Record<string, any>
  }
  category: 'authentication' | 'network' | 'behavior' | 'privilege' | 'temporal' | 'informational' | 'security' | 'behavioral' | 'correlation'
  severity: 'low' | 'medium' | 'high' | 'critical' | 'info'
  enabled: boolean
  timeWindow: number // minutes to analyze
  thresholds: Record<string, number>

  // The main analysis function
  analyze(events: AuthEvent[], context: AnalyticsContext): Promise<Anomaly[]>

  // Validation and metadata methods
  validate(): { valid: boolean; errors: string[] }
  getMetadata(): any

  // Metadata
  version: string
  author: string
  created: Date
  updated: Date
}

export interface RuleConfig {
  id?: string
  name?: string
  description?: string
  detailedDescription?: string
  category?: 'authentication' | 'network' | 'behavior' | 'privilege' | 'temporal' | 'informational' | 'security' | 'behavioral' | 'correlation'
  severity?: 'low' | 'medium' | 'high' | 'critical' | 'info'
  enabled?: boolean
  timeWindow?: number
  thresholds?: Record<string, number>
  version?: string
  author?: string
  created?: Date
  updated?: Date
}

export interface AnalyticsContext {
  sessionId: string
  organizationId: string
  timeRange: {
    start: Date
    end: Date
  }
  userProfiles?: UserProfile[]
  ipIntelligence?: IpIntelligence[]
  sharpHoundData?: SharpHoundData
  dataType?: 'auth-logs' | 'sharphound'
}

export interface SharpHoundData {
  users: SharpHoundUser[]
  computers: SharpHoundComputer[]
  groups: SharpHoundGroup[]
  domains: SharpHoundDomain[]
  ous: SharpHoundOU[]
  gpos: SharpHoundGPO[]
  containers: SharpHoundContainer[]
  certificates: SharpHoundCertificate[]
}

export interface SharpHoundUser {
  Properties: {
    domain: string
    name: string
    distinguishedname: string
    domainsid: string
    samaccountname: string
    isaclprotected: boolean
    description?: string
    whencreated: number
    sensitive: boolean
    dontreqpreauth: boolean
    passwordnotreqd: boolean
    unconstraineddelegation: boolean
    pwdneverexpires: boolean
    enabled: boolean
    trustedtoauth: boolean
    lastlogon: number
    lastlogontimestamp: number
    pwdlastset: number
    serviceprincipalnames: string[]
    hasspn: boolean
    displayname?: string
    email?: string
    title?: string
    homedirectory?: string
    userpassword?: string
    unixpassword?: string
    unicodepassword?: string
    sfupassword?: string
    logonscript?: string
    admincount: boolean
    sidhistory: string[]
  }
  AllowedToDelegate: string[]
  PrimaryGroupSID: string
  HasSIDHistory: string[]
  SPNTargets: string[]
  Aces: Array<{
    PrincipalSID: string
    PrincipalType: string
    RightName: string
    IsInherited: boolean
  }>
}

export interface SharpHoundComputer {
  Properties: {
    domain: string
    name: string
    distinguishedname: string
    domainsid: string
    samaccountname: string
    haslaps: boolean
    isaclprotected: boolean
    description?: string
    whencreated: number
    enabled: boolean
    unconstraineddelegation: boolean
    trustedtoauth: boolean
    isdc: boolean
    lastlogon: number
    lastlogontimestamp: number
    pwdlastset: number
    serviceprincipalnames: string[]
    email?: string
    operatingsystem?: string
  }
  AllowedToDelegate: string[]
  PrimaryGroupSID: string
  AllowedToAct: string[]
  Aces: Array<{
    PrincipalSID: string
    PrincipalType: string
    RightName: string
    IsInherited: boolean
  }>
}

export interface SharpHoundGroup {
  Properties: {
    domain: string
    name: string
    distinguishedname: string
    domainsid: string
    samaccountname: string
    isaclprotected: boolean
    description?: string
    whencreated: number
    admincount: boolean
  }
  Aces: Array<{
    PrincipalSID: string
    PrincipalType: string
    RightName: string
    IsInherited: boolean
  }>
}

export interface SharpHoundDomain {
  Properties: {
    domain: string
    name: string
    distinguishedname: string
    domainsid: string
    highvalue: boolean
    description?: string
    whencreated: number
    machinaccountquota: number
    functionallevel: string
  }
  Aces: Array<{
    PrincipalSID: string
    PrincipalType: string
    RightName: string
    IsInherited: boolean
  }>
  Links: Array<{
    IsEnforced: boolean
    GUID: string
  }>
  ChildObjects: string[]
  GPOChanges: Array<{
    GUID: string
    IsDeleted: boolean
    ChangedDate: number
  }>
}

export interface SharpHoundOU {
  Properties: {
    domain: string
    name: string
    distinguishedname: string
    domainsid: string
    description?: string
    whencreated: number
  }
  Aces: Array<{
    PrincipalSID: string
    PrincipalType: string
    RightName: string
    IsInherited: boolean
  }>
  Links: Array<{
    IsEnforced: boolean
    GUID: string
  }>
}

export interface SharpHoundGPO {
  Properties: {
    domain: string
    name: string
    distinguishedname: string
    domainsid: string
    gpcpath: string
    description?: string
    whencreated: number
    whenchanged: number
  }
  Aces: Array<{
    PrincipalSID: string
    PrincipalType: string
    RightName: string
    IsInherited: boolean
  }>
}

export interface SharpHoundContainer {
  Properties: {
    domain: string
    name: string
    distinguishedname: string
    domainsid: string
    description?: string
    whencreated: number
  }
  Aces: Array<{
    PrincipalSID: string
    PrincipalType: string
    RightName: string
    IsInherited: boolean
  }>
}

export interface SharpHoundCertificate {
  Properties: {
    domain: string
    templatename: string
    distinguishedname: string
    description?: string
    certificateusages: string[]
    certificateapplicationpolicy: string[]
    requiresmanagerapproval: boolean
    authenticationenabled: boolean
    enrollmentservers: string[]
    authorizedsignaturesrequired: number
    issuancerequirements: string[]
    validityperiod: string
    renewalperiod: string
    supersededtemplates: string[]
    schemaversion: number
  }
  Aces: Array<{
    PrincipalSID: string
    PrincipalType: string
    RightName: string
    IsInherited: boolean
  }>
}

export interface UserProfile {
  userName: string
  domain: string
  department?: string
  title?: string
  privileged: boolean
  enabled: boolean
  groups: string[]
  normalLoginHours?: { start: number; end: number }
  normalLocations?: string[]
  // Service Account specific fields
  isServiceAccount?: boolean
  serviceAccountType?: string
  serviceAccountIndicators?: string[]
  passwordNeverExpires?: boolean
  cannotChangePassword?: boolean
  accountExpirationDate?: Date
  lastBadPasswordAttempt?: Date
  lastLogonDate?: Date
  passwordLastSet?: Date
  badPasswordCount?: number
  accountAgeDays?: number
}

export interface IpIntelligence {
  ip: string
  country?: string
  region?: string
  city?: string
  latitude?: number
  longitude?: number
  isp?: string
  isVpn: boolean
  isTor: boolean
  isMalicious: boolean
  riskScore: number
}

// ADCS (Active Directory Certificate Services) specific types
export interface CertificateEvent extends AuthEvent {
  certificateTemplate?: string
  certificateAuthority?: string
  requestId?: string
  subjectName?: string
  subjectAlternativeNames?: string[]
  issuerName?: string
  serialNumber?: string
  thumbprint?: string
  validityStart?: Date
  validityEnd?: Date
  keyUsage?: string[]
  extendedKeyUsage?: string[]
  enrollmentFlags?: number
  certificateNameFlags?: number
  applicationPolicies?: string[]
  issuancePolicies?: string[]
  schemaVersion?: number
  requestType?: string
  enrollmentMethod?: string
}

export interface CertificateTemplate {
  name: string
  displayName?: string
  schemaVersion: number
  enabled: boolean
  enrollmentFlags: number
  certificateNameFlags: number
  validityPeriod?: string
  renewalPeriod?: string
  extendedKeyUsage?: string[]
  applicationPolicies?: string[]
  issuancePolicies?: string[]
  permissions?: CertificateTemplatePermission[]
  vulnerableTo?: string[] // ESC vulnerabilities this template is vulnerable to
}

export interface CertificateTemplatePermission {
  identity: string
  rights: string[]
  inheritance: boolean
}

export interface CertificateAuthority {
  name: string
  displayName?: string
  dnsName: string
  enabled: boolean
  auditFilter: number
  interfaceFlags: number
  editFlags: number
  securityFlags: number
  templates: string[]
  vulnerableTo?: string[] // ESC vulnerabilities this CA is vulnerable to
}

export interface ADCSContext extends AnalyticsContext {
  certificateTemplates?: CertificateTemplate[]
  certificateAuthorities?: CertificateAuthority[]
  adcsConfiguration?: {
    auditFilterEnabled: boolean
    interfaceFlags: number
    editFlags: number
    webEnrollmentEnabled: boolean
    webEnrollmentUrl?: string
    webEnrollmentHttpsOnly: boolean
  }
}

// ESC (Escalation) vulnerability types
export type ESCVulnerability =
  | 'ESC1' | 'ESC2' | 'ESC3' | 'ESC4' | 'ESC5' | 'ESC6'
  | 'ESC7' | 'ESC8' | 'ESC9' | 'ESC11' | 'ESC13' | 'ESC15' | 'ESC16'

export interface ESCDetectionResult {
  vulnerability: ESCVulnerability
  severity: 'low' | 'medium' | 'high' | 'critical'
  confidence: number
  affectedEntities: Array<{
    type: 'certificateTemplate' | 'certificateAuthority' | 'user' | 'computer' | 'ip'
    id: string
    name: string
  }>
  evidence: Record<string, any>
  remediation: string[]
}

// ADCS-specific event IDs
export const ADCSEventIds = {
  CERTIFICATE_REQUEST_RECEIVED: '4886',
  CERTIFICATE_ISSUED: '4887',
  CERTIFICATE_REQUEST_DENIED: '4888',
  CERTIFICATE_TEMPLATE_PERMISSIONS_CHANGED: '4898',
  CERTIFICATE_TEMPLATE_UPDATED: '4899',
  CERTIFICATE_TEMPLATE_LOADED: '4900',
  CERTIFICATE_REQUEST_SUBMITTED: '53',
  CERTIFICATE_ISSUED_DETAILED: '54',
  // Additional event IDs from Splunk analytics
  CA_BACKUP_STARTED: '4876',
  CA_BACKUP_COMPLETED: '4877',
  CERTIFICATE_EXPORT: '1007',
  POWERSHELL_SCRIPT_BLOCK: '4104',
  PROCESS_CREATION: '4688',
  FILE_CREATION: '11'
} as const

// Certificate file extensions that indicate potential theft/export
export const CertificateFileExtensions = [
  '.pfx', '.p12', '.p7b', '.cer', '.crt', '.der', '.pem',
  '.keyx.rsa.pvk', '.sign.rsa.pvk', '.sign.dsa.pvk',
  '.dsa.ec.p8k', '.dh.ec.p8k', '.ccache'
] as const

// Certificate-related process names
export const CertificateTools = [
  'certutil.exe', 'certipy.exe', 'certify.exe',
  'mimikatz.exe', 'certreq.exe', 'powershell.exe'
] as const

export interface AnalyticsResult {
  sessionId: string
  ruleResults: {
    ruleId: string
    ruleName: string
    executed: boolean
    executionTime: number
    anomaliesFound: number
    error?: string
  }[]
  anomalies: Anomaly[]
  summary: {
    totalRulesExecuted: number
    totalAnomalies: number
    highestSeverity: 'low' | 'medium' | 'high' | 'critical' | null
    executionTime: number
  }
  timestamp: Date
}
