import { supabase } from './supabase';
import JSZip from 'jszip';

export interface SharpHoundUser {
  Properties: {
    domain: string;
    name: string;
    distinguishedname: string;
    domainsid: string;
    samaccountname: string;
    isaclprotected: boolean;
    description?: string;
    whencreated: number;
    sensitive: boolean;
    dontreqpreauth: boolean;
    passwordnotreqd: boolean;
    unconstraineddelegation: boolean;
    pwdneverexpires: boolean;
    enabled: boolean;
    trustedtoauth: boolean;
    lastlogon: number;
    lastlogontimestamp: number;
    pwdlastset: number;
    serviceprincipalnames: string[];
    hasspn: boolean;
    displayname?: string;
    email?: string;
    title?: string;
    homedirectory?: string;
    userpassword?: string;
    unixpassword?: string;
    unicodepassword?: string;
    sfupassword?: string;
    logonscript?: string;
    admincount: boolean;
    sidhistory: string[];
  };
  AllowedToDelegate: string[];
  PrimaryGroupSID: string;
  HasSIDHistory: string[];
  SPNTargets: string[];
  Aces: Array<{
    PrincipalSID: string;
    PrincipalType: string;
    RightName: string;
    IsInherited: boolean;
  }>;
}

export interface SharpHoundComputer {
  Properties: {
    domain: string;
    name: string;
    distinguishedname: string;
    domainsid: string;
    samaccountname: string;
    haslaps: boolean;
    isaclprotected: boolean;
    description?: string;
    whencreated: number;
    enabled: boolean;
    unconstraineddelegation: boolean;
    trustedtoauth: boolean;
    isdc: boolean;
    lastlogon: number;
    lastlogontimestamp: number;
    pwdlastset: number;
    serviceprincipalnames: string[];
    email?: string;
    operatingsystem?: string;
  };
  AllowedToDelegate: string[];
  PrimaryGroupSID: string;
  AllowedToAct: string[];
  Aces: Array<{
    PrincipalSID: string;
    PrincipalType: string;
    RightName: string;
    IsInherited: boolean;
  }>;
}

export interface SharpHoundGroup {
  Properties: {
    domain: string;
    name: string;
    distinguishedname: string;
    domainsid: string;
    samaccountname: string;
    isaclprotected: boolean;
    description?: string;
    whencreated: number;
    admincount: boolean;
  };
  Aces: Array<{
    PrincipalSID: string;
    PrincipalType: string;
    RightName: string;
    IsInherited: boolean;
  }>;
}

export interface SharpHoundCollection {
  id: string;
  user_id: string;
  name: string;
  description?: string;
  collection_type: 'sharphound';
  created_at: string;
  files: SharpHoundFile[];
  metadata: {
    total_users: number;
    total_computers: number;
    total_groups: number;
    total_domains: number;
    total_ous: number;
    collection_timestamp: string;
  };
}

export interface SharpHoundFile {
  filename: string;
  type: 'users' | 'computers' | 'groups' | 'domains' | 'ous' | 'gpos' | 'containers' | 'certificates' | 'other';
  data: any[];
  processed_at: string;
}

export class SharpHoundService {
  /**
   * Extract and process SharpHound ZIP file
   */
  static async processSharpHoundZip(zipFile: File): Promise<SharpHoundCollection> {
    const zip = new JSZip();
    const zipData = await zip.loadAsync(zipFile);

    const files: SharpHoundFile[] = [];
    const collectionId = crypto.randomUUID();

    // Process each file in the ZIP
    for (const [filename, file] of Object.entries(zipData.files)) {
      if (!file.dir && filename.endsWith('.json')) {
        try {
          const content = await file.async('text');
          const data = JSON.parse(content);

          const fileType = this.determineFileType(filename);
          const processedData = this.processFileData(data, fileType);

          files.push({
            filename,
            type: fileType,
            data: processedData,
            processed_at: new Date().toISOString()
          });
        } catch (error) {
          console.error(`Error processing ${filename}:`, error);
        }
      }
    }

    // Create collection metadata
    const metadata = this.generateCollectionMetadata(files);

    return {
      id: collectionId,
      user_id: '', // Will be set when uploading
      name: `SharpHound Collection ${new Date().toISOString().split('T')[0]}`,
      collection_type: 'sharphound',
      created_at: new Date().toISOString(),
      files,
      metadata
    };
  }

  /**
   * Process individual SharpHound JSON files
   */
  static async processSharpHoundFiles(files: FileList): Promise<SharpHoundCollection> {
    const sharpHoundFiles: SharpHoundFile[] = [];
    const collectionId = crypto.randomUUID();

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      if (file.name.endsWith('.json')) {
        try {
          const content = await file.text();
          const data = JSON.parse(content);

          const fileType = this.determineFileType(file.name);
          const processedData = this.processFileData(data, fileType);

          sharpHoundFiles.push({
            filename: file.name,
            type: fileType,
            data: processedData,
            processed_at: new Date().toISOString()
          });
        } catch (error) {
          console.error(`Error processing ${file.name}:`, error);
        }
      }
    }

    const metadata = this.generateCollectionMetadata(sharpHoundFiles);

    return {
      id: collectionId,
      user_id: '', // Will be set when uploading
      name: `SharpHound Collection ${new Date().toISOString().split('T')[0]}`,
      collection_type: 'sharphound',
      created_at: new Date().toISOString(),
      files: sharpHoundFiles,
      metadata
    };
  }

  /**
   * Determine the type of SharpHound file based on filename
   */
  private static determineFileType(filename: string): SharpHoundFile['type'] {
    const lowerFilename = filename.toLowerCase();

    if (lowerFilename.includes('user')) return 'users';
    if (lowerFilename.includes('computer')) return 'computers';
    if (lowerFilename.includes('group')) return 'groups';
    if (lowerFilename.includes('domain')) return 'domains';
    if (lowerFilename.includes('ou')) return 'ous';
    if (lowerFilename.includes('gpo')) return 'gpos';
    if (lowerFilename.includes('container')) return 'containers';
    if (lowerFilename.includes('cert') || lowerFilename.includes('ca')) return 'certificates';

    return 'other';
  }

  /**
   * Process file data based on type
   */
  private static processFileData(data: any, type: SharpHoundFile['type']): any[] {
    if (!data || !Array.isArray(data.data)) return [];

    switch (type) {
      case 'users':
        return data.data.map((user: any) => this.processUserData(user));
      case 'computers':
        return data.data.map((computer: any) => this.processComputerData(computer));
      case 'groups':
        return data.data.map((group: any) => this.processGroupData(group));
      default:
        return data.data;
    }
  }

  /**
   * Process user data to ensure consistent format
   */
  private static processUserData(user: any): SharpHoundUser {
    return {
      Properties: {
        domain: user.Properties?.domain || '',
        name: user.Properties?.name || '',
        distinguishedname: user.Properties?.distinguishedname || '',
        domainsid: user.Properties?.domainsid || '',
        samaccountname: user.Properties?.samaccountname || '',
        isaclprotected: user.Properties?.isaclprotected || false,
        description: user.Properties?.description,
        whencreated: user.Properties?.whencreated || 0,
        sensitive: user.Properties?.sensitive || false,
        dontreqpreauth: user.Properties?.dontreqpreauth || false,
        passwordnotreqd: user.Properties?.passwordnotreqd || false,
        unconstraineddelegation: user.Properties?.unconstraineddelegation || false,
        pwdneverexpires: user.Properties?.pwdneverexpires || false,
        enabled: user.Properties?.enabled || false,
        trustedtoauth: user.Properties?.trustedtoauth || false,
        lastlogon: user.Properties?.lastlogon || 0,
        lastlogontimestamp: user.Properties?.lastlogontimestamp || 0,
        pwdlastset: user.Properties?.pwdlastset || 0,
        serviceprincipalnames: user.Properties?.serviceprincipalnames || [],
        hasspn: user.Properties?.hasspn || false,
        displayname: user.Properties?.displayname,
        email: user.Properties?.email,
        title: user.Properties?.title,
        homedirectory: user.Properties?.homedirectory,
        userpassword: user.Properties?.userpassword,
        unixpassword: user.Properties?.unixpassword,
        unicodepassword: user.Properties?.unicodepassword,
        sfupassword: user.Properties?.sfupassword,
        logonscript: user.Properties?.logonscript,
        admincount: user.Properties?.admincount || false,
        sidhistory: user.Properties?.sidhistory || []
      },
      AllowedToDelegate: user.AllowedToDelegate || [],
      PrimaryGroupSID: user.PrimaryGroupSID || '',
      HasSIDHistory: user.HasSIDHistory || [],
      SPNTargets: user.SPNTargets || [],
      Aces: user.Aces || []
    };
  }

  /**
   * Process computer data
   */
  private static processComputerData(computer: any): SharpHoundComputer {
    return {
      Properties: {
        domain: computer.Properties?.domain || '',
        name: computer.Properties?.name || '',
        distinguishedname: computer.Properties?.distinguishedname || '',
        domainsid: computer.Properties?.domainsid || '',
        samaccountname: computer.Properties?.samaccountname || '',
        haslaps: computer.Properties?.haslaps || false,
        isaclprotected: computer.Properties?.isaclprotected || false,
        description: computer.Properties?.description,
        whencreated: computer.Properties?.whencreated || 0,
        enabled: computer.Properties?.enabled || false,
        unconstraineddelegation: computer.Properties?.unconstraineddelegation || false,
        trustedtoauth: computer.Properties?.trustedtoauth || false,
        isdc: computer.Properties?.isdc || false,
        lastlogon: computer.Properties?.lastlogon || 0,
        lastlogontimestamp: computer.Properties?.lastlogontimestamp || 0,
        pwdlastset: computer.Properties?.pwdlastset || 0,
        serviceprincipalnames: computer.Properties?.serviceprincipalnames || [],
        email: computer.Properties?.email,
        operatingsystem: computer.Properties?.operatingsystem
      },
      AllowedToDelegate: computer.AllowedToDelegate || [],
      PrimaryGroupSID: computer.PrimaryGroupSID || '',
      AllowedToAct: computer.AllowedToAct || [],
      Aces: computer.Aces || []
    };
  }

  /**
   * Process group data
   */
  private static processGroupData(group: any): SharpHoundGroup {
    return {
      Properties: {
        domain: group.Properties?.domain || '',
        name: group.Properties?.name || '',
        distinguishedname: group.Properties?.distinguishedname || '',
        domainsid: group.Properties?.domainsid || '',
        samaccountname: group.Properties?.samaccountname || '',
        isaclprotected: group.Properties?.isaclprotected || false,
        description: group.Properties?.description,
        whencreated: group.Properties?.whencreated || 0,
        admincount: group.Properties?.admincount || false
      },
      Aces: group.Aces || []
    };
  }

  /**
   * Generate collection metadata
   */
  private static generateCollectionMetadata(files: SharpHoundFile[]) {
    const stats = {
      total_users: 0,
      total_computers: 0,
      total_groups: 0,
      total_domains: 0,
      total_ous: 0
    };

    files.forEach((file: any) => {
      switch (file.type) {
        case 'users':
          stats.total_users += file.data.length;
          break;
        case 'computers':
          stats.total_computers += file.data.length;
          break;
        case 'groups':
          stats.total_groups += file.data.length;
          break;
        case 'domains':
          stats.total_domains += file.data.length;
          break;
        case 'ous':
          stats.total_ous += file.data.length;
          break;
      }
    });

    return {
      ...stats,
      collection_timestamp: new Date().toISOString()
    };
  }

  /**
   * Save SharpHound collection to database
   */
  static async saveCollection(collection: SharpHoundCollection, userId: string): Promise<string> {
    console.log('SharpHound: Starting database save for collection:', collection.id);

    // Update user_id
    collection.user_id = userId;

    // First, store the SharpHound data in Supabase storage
    console.log('SharpHound: Storing data in Supabase storage...');

    const collectionJson = JSON.stringify(collection);
    const blob = new Blob([collectionJson], { type: 'application/json' });
    const file = new File([blob], `sharphound-collection-${collection.id}.json`, { type: 'application/json' });

    // Upload to Supabase storage
    const { data: uploadData, error: uploadError } = await supabase.storage
      .from('analysis-data')
      .upload(`sharphound/${collection.id}/data.json`, file, {
        cacheControl: '3600',
        upsert: false
      });

    if (uploadError) {
      console.error('SharpHound: Storage upload error:', uploadError);
      // Don't throw here - we can still save metadata even if storage fails
    } else {
      console.log('SharpHound: Data stored in Supabase storage');
    }

    // Save metadata to database
    const sessionData = {
      session_name: collection.name,
      uploaded_at: collection.created_at,
      file_name: `sharphound-collection-${collection.id}`,
      file_size_bytes: collectionJson.length,
      event_count: collection.metadata.total_users + collection.metadata.total_computers + collection.metadata.total_groups,
      anomaly_count: 0, // Will be calculated by analytics
      storage_path: `sharphound/${collection.id}`
    };

    console.log('SharpHound: Inserting session metadata:', sessionData);

    const { data, error } = await supabase
      .from('analysis_sessions')
      .insert(sessionData)
      .select()
      .single();

    if (error) {
      console.error('SharpHound: Database insert error:', error);
      throw error;
    }

    console.log('SharpHound: Successfully saved collection with ID:', data.id);
    return data.id;
  }

  /**
   * Get user's SharpHound collections
   */
  static async getUserCollections(userId: string): Promise<SharpHoundCollection[]> {
    const { data, error } = await supabase
      .from('analysis_sessions')
      .select('*')
      .like('storage_path', 'sharphound/%')
      .order('uploaded_at', { ascending: false });

    if (error) {
      throw error;
    }

    // Transform the data to match SharpHoundCollection format
    return data?.map((session: any) => ({
      id: session.storage_path.split('/')[1],
      user_id: session.user_id,
      name: session.session_name,
      collection_type: 'sharphound' as const,
      created_at: session.uploaded_at,
      files: [], // Would need to be stored separately
      metadata: {
        total_users: 0,
        total_computers: 0,
        total_groups: 0,
        total_domains: 0,
        total_ous: 0,
        collection_timestamp: session.uploaded_at
      }
    })) || [];
  }
}
