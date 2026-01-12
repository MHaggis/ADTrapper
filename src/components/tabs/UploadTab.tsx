import React, { useState } from 'react';
import { Download, Upload, ExternalLink, ChevronDown, ChevronRight } from 'lucide-react';

interface UploadTabProps {
  darkMode: boolean;
  uploadProgress: number;
  isAnalyzing: boolean;
  handleFileUpload: (event: React.ChangeEvent<HTMLInputElement>) => void;
}

export const UploadTab: React.FC<UploadTabProps> = ({
  darkMode,
  uploadProgress,
  isAnalyzing,
  handleFileUpload
}) => {
  // State for expandable sections
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['powershell']));

  // Toggle expandable section
  const toggleSection = (sectionId: string) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(sectionId)) {
      newExpanded.delete(sectionId);
    } else {
      newExpanded.add(sectionId);
    }
    setExpandedSections(newExpanded);
  };

  // Download PowerShell script
  const downloadPowerShellScript = () => {
    const scriptUrl = '/capture.ps1';
    const link = document.createElement('a');
    link.href = scriptUrl;
    link.download = 'adtrapper-capture.ps1';
    link.click();
  };

  const cardClasses = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';

  // Expandable Section Component
  const ExpandableSection = ({
    id,
    title,
    icon,
    iconBg,
    iconColor,
    children,
    badge
  }: {
    id: string;
    title: string;
    icon: React.ReactNode;
    iconBg: string;
    iconColor: string;
    children: React.ReactNode;
    badge?: string;
  }) => {
    const isExpanded = expandedSections.has(id);

    return (
      <div className={`${cardClasses} border rounded-lg overflow-hidden`}>
        <button
          onClick={() => toggleSection(id)}
          className="w-full p-4 text-left hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 ${iconBg} rounded-lg flex items-center justify-center flex-shrink-0`}>
                {icon}
              </div>
              <div>
                <h3 className="font-semibold flex items-center gap-2">
                  {title}
                  {badge && (
                    <span className="text-xs bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 px-2 py-1 rounded-full font-medium">
                      {badge}
                    </span>
                  )}
                </h3>
              </div>
            </div>
            {isExpanded ? (
              <ChevronDown className="w-5 h-5 text-gray-500" />
            ) : (
              <ChevronRight className="w-5 h-5 text-gray-500" />
            )}
          </div>
        </button>
        {isExpanded && (
          <div className="px-4 pb-4">
            {children}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="max-w-4xl mx-auto">
      <div className="text-center mb-8">
        <Upload className="w-16 h-16 mx-auto text-blue-500 mb-4" />
        <h2 className="text-3xl font-bold mb-2">ADTrapper Data Collection</h2>
        <p className="text-gray-500">Collect and upload authentication logs for security analysis</p>
      </div>

      {/* Step 1: Collection */}
      <div className="mb-8">
        <div className="text-center mb-6">
          <h3 className="text-2xl font-bold text-blue-600 dark:text-blue-400 mb-2">Step 1: Collection</h3>
          <p className="text-gray-600 dark:text-gray-400">Choose your preferred method to collect authentication data</p>
        </div>

        <div className="space-y-4">
          {/* ADTrapper PowerShell Script */}
          <ExpandableSection
            id="powershell"
            title="ADTrapper PowerShell Script"
            icon={<Download className="w-5 h-5 text-blue-500" />}
            iconBg="bg-blue-500/10"
            iconColor="text-blue-500"
            badge="Recommended"
          >
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Download our PowerShell script to collect Windows authentication logs from your domain controllers or workstations.
            </p>

            <div className="grid md:grid-cols-2 gap-4 mb-4">
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>Extracts Security Event Log data</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>Enriches with Active Directory data</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>Adds GeoIP intelligence</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>Outputs JSON for ADTrapper</span>
              </div>
            </div>

            <button
              onClick={downloadPowerShellScript}
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition-colors mb-4"
            >
              <Download size={16} />
              Download capture.ps1
            </button>

            <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg border border-blue-200 dark:border-blue-800">
              <p className="text-sm text-blue-700 dark:text-blue-300 mb-2">
                <strong>Usage Examples:</strong>
              </p>
              <div className="space-y-2 text-sm">
                <code className="text-xs bg-blue-100 dark:bg-blue-900/40 p-2 rounded block font-mono">
                  .\capture.ps1 -Hours 24 -Format json
                </code>
                <code className="text-xs bg-blue-100 dark:bg-blue-900/40 p-2 rounded block font-mono">
                  .\capture.ps1 -Hours 24 -EnrichWithAD -ADCS -Format json
                </code>
              </div>
            </div>
          </ExpandableSection>

          {/* SharpHound AD Collector */}
          <ExpandableSection
            id="sharphound"
            title="SharpHound AD Data Collector"
            icon={<Download className="w-5 h-5 text-purple-500" />}
            iconBg="bg-purple-500/10"
            iconColor="text-purple-500"
            badge="Advanced"
          >
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Download SharpHound to collect comprehensive Active Directory data including users, groups, computers, permissions, and security relationships.
            </p>

            <div className="grid md:grid-cols-2 gap-4 mb-4">
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-purple-500 rounded-full"></span>
                <span>Collects full AD object properties</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-purple-500 rounded-full"></span>
                <span>Extracts security permissions & ACLs</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-purple-500 rounded-full"></span>
                <span>Captures group memberships & trusts</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-purple-500 rounded-full"></span>
                <span>Outputs JSON for ADTrapper analysis</span>
              </div>
            </div>

            <div className="flex gap-3 mb-4">
              <a
                href="https://github.com/SpecterOps/SharpHound/releases"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 bg-purple-500 text-white rounded-lg hover:bg-purple-600 transition-colors"
              >
                <Download size={16} />
                Download SharpHound
                <ExternalLink size={14} />
              </a>
              <a
                href="https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors"
              >
                Documentation
                <ExternalLink size={14} />
              </a>
            </div>

            <div className="bg-purple-50 dark:bg-purple-900/20 p-3 rounded-lg border border-purple-200 dark:border-purple-800">
              <p className="text-sm text-purple-700 dark:text-purple-300 mb-1">
                <strong>Example Usage:</strong>
              </p>
              <code className="text-xs font-mono text-purple-800 dark:text-purple-200">
                SharpHound.exe -c All -d YOURDOMAIN.COM -o sharphound-data
              </code>
            </div>
          </ExpandableSection>

          {/* Manual Event Log Export */}
          <ExpandableSection
            id="manual"
            title="Manual Event Log Export"
            icon={<Download className="w-5 h-5 text-green-500" />}
            iconBg="bg-green-500/10"
            iconColor="text-green-500"
            badge="Direct Upload"
          >
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Export Windows Event Logs directly using Event Viewer or PowerShell commands.
            </p>

            <div className="grid md:grid-cols-2 gap-4 mb-6">
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>Parses Security Event Log events</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>Extracts AD CS certificate operations</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>Analyzes SMB share access patterns</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>Supports XML, JSON formats</span>
              </div>
            </div>

            {/* Quick Export Commands */}
            <div className="space-y-3 mb-6">
              <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                <h4 className="font-semibold text-green-600 dark:text-green-400 mb-2">Quick Export Commands</h4>

                <div className="space-y-3">
                  <div>
                    <p className="text-sm font-medium mb-1">Authentication Events:</p>
                    <code className="text-xs bg-gray-100 dark:bg-gray-700 p-2 rounded block font-mono">
                      Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4624 or EventID=4625)]]" -MaxEvents 5000 | ConvertTo-Json | Out-File "auth_events.json"
                    </code>
                  </div>

                  <div>
                    <p className="text-sm font-medium mb-1">AD CS Events:</p>
                    <code className="text-xs bg-gray-100 dark:bg-gray-700 p-2 rounded block font-mono">
                      Get-WinEvent -LogName "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" -MaxEvents 3000 | ConvertTo-Json | Out-File "adcs_events.json"
                    </code>
                  </div>
                </div>
              </div>

              <div className="bg-amber-50 dark:bg-amber-900/20 p-3 rounded-lg border border-amber-200 dark:border-amber-800">
                <p className="text-sm text-amber-800 dark:text-amber-200">
                  💡 <strong>Tip:</strong> Run PowerShell as Administrator for best results. Use JSON format to avoid parsing issues.
                </p>
              </div>
            </div>
          </ExpandableSection>
        </div>
      </div>

      {/* Step 2: Upload */}
      <div className={`${cardClasses} rounded-xl shadow-lg`}>
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="text-center">
            <h3 className="text-2xl font-bold text-green-600 dark:text-green-400 mb-2">Step 2: Upload</h3>
            <p className="text-gray-600 dark:text-gray-400">
              Upload your collected authentication data files for analysis
            </p>
          </div>
        </div>

        <div className="p-8">
          <div className={`border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-8 text-center ${isAnalyzing ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : ''}`}>
            {isAnalyzing ? (
              <div className="space-y-4">
                <div className="w-16 h-16 mx-auto border-4 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                <div>
                  <p className="font-medium">Processing authentication events...</p>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Running analytics detection rules</p>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mt-3 max-w-xs mx-auto">
                    <div
                      className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${uploadProgress}%` }}
                    ></div>
                  </div>
                  <p className="text-sm text-gray-500 mt-2">{uploadProgress}% complete</p>
                </div>
              </div>
            ) : (
              <div>
                <Upload className="w-12 h-12 mx-auto text-gray-400 mb-4" />
                <p className="text-xl mb-2">Drop your authentication log files here</p>
                <p className="text-gray-500 mb-6">or click to browse</p>
                <label className="inline-flex items-center gap-2 px-6 py-3 bg-green-500 text-white rounded-lg cursor-pointer hover:bg-green-600 transition-colors">
                  <Upload size={20} />
                  Choose Files
                  <input
                    type="file"
                    accept=".json,.xml,.zip"
                    multiple
                    className="hidden"
                    onChange={handleFileUpload}
                  />
                </label>
                <p className="text-xs text-gray-500 mt-4">
                  Supported formats: JSON (preferred), XML (Event Logs), ZIP (collections)
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
