export type DataCategory =
  | 'IDENTIFIER' // Email, phone, username, device ID, IP address
  | 'FINANCIAL' // Card numbers, bank accounts, balances
  | 'LOCATION' // GPS coordinates, zip code, geofence
  | 'BEHAVIORAL' // Keystrokes, session playback, clicks, form inputs
  | 'TECHNICAL'; // OS, battery, screen size, user agent

export type DestinationRiskTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface ThirdPartyDestination {
  domain: string;
  entityName: string;
  category: 'AD_NETWORK' | 'DATA_BROKER' | 'ANALYTICS' | 'PAYMENT' | 'INFRASTRUCTURE';
  riskTier: DestinationRiskTier;
  knownTrackers: string[];
}

export interface EgressFlow {
  id: string;
  timestamp: string;
  sourceModule: string;
  destinationDomain: string;
  httpMethod: string;
  endpoint: string;
  payload: Record<string, any>;
}

export interface DetectedExposure {
  flowId: string;
  destinationDomain: string;
  entityName: string;
  dataCategory: DataCategory;
  field: string;
  valueMasked: string;
  isDeclaredInPolicy: boolean;
  severity: DestinationRiskTier;
  violationRationale: string;
}

export interface DataShadowAuditReport {
  timestamp: string;
  totalFlowsAnalyzed: number;
  totalExposures: number;
  undeclaredExposuresCount: number;
  privacyScore: number; // 0 to 100
  exposures: DetectedExposure[];
  flowsByCategory: Record<DataCategory, number>;
}
