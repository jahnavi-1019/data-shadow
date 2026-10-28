import {
  EgressFlow,
  ThirdPartyDestination,
  DetectedExposure,
  DataShadowAuditReport,
  DataCategory
} from './types.js';
import { DataClassifier } from './data-classifier.js';

export class FlowAnalyzer {
  private static KNOWN_DESTINATIONS: Record<string, ThirdPartyDestination> = {
    'ads.facebook.com': {
      domain: 'ads.facebook.com',
      entityName: 'Meta Platforms (Ad Network)',
      category: 'AD_NETWORK',
      riskTier: 'HIGH',
      knownTrackers: ['pixel', 'fbevents.js']
    },
    'tracker.databroker.io': {
      domain: 'tracker.databroker.io',
      entityName: 'OmniData Broker',
      category: 'DATA_BROKER',
      riskTier: 'CRITICAL',
      knownTrackers: ['fingerprinter', 'cross-app-id']
    },
    'telemetry.hotjar.com': {
      domain: 'telemetry.hotjar.com',
      entityName: 'Hotjar Session Replay',
      category: 'ANALYTICS',
      riskTier: 'HIGH',
      knownTrackers: ['session-recorder']
    },
    'api.stripe.com': {
      domain: 'api.stripe.com',
      entityName: 'Stripe Payments',
      category: 'PAYMENT',
      riskTier: 'LOW',
      knownTrackers: []
    }
  };

  /**
   * Analyzes a collection of network egress flows against declared policy scopes.
   */
  public static analyzeFlows(
    flows: EgressFlow[],
    declaredCategories: Set<DataCategory>
  ): DataShadowAuditReport {
    const exposures: DetectedExposure[] = [];
    const flowsByCategory: Record<DataCategory, number> = {
      IDENTIFIER: 0,
      FINANCIAL: 0,
      LOCATION: 0,
      BEHAVIORAL: 0,
      TECHNICAL: 0
    };

    for (const flow of flows) {
      const dest = this.KNOWN_DESTINATIONS[flow.destinationDomain] || {
        domain: flow.destinationDomain,
        entityName: flow.destinationDomain,
        category: 'INFRASTRUCTURE',
        riskTier: 'LOW',
        knownTrackers: []
      };

      for (const [key, val] of Object.entries(flow.payload)) {
        const category = DataClassifier.classifyField(key, val);
        flowsByCategory[category]++;

        const isDeclared = declaredCategories.has(category);

        // If high risk category sent to third-party ad network or broker, or undeclared in policy
        const isSuspicious =
          !isDeclared ||
          dest.category === 'DATA_BROKER' ||
          (dest.category === 'AD_NETWORK' && (category === 'LOCATION' || category === 'IDENTIFIER')) ||
          (category === 'BEHAVIORAL' && dest.category !== 'INFRASTRUCTURE');

        if (isSuspicious) {
          let severity = dest.riskTier;
          let violationRationale = '';

          if (!isDeclared) {
            severity = severity === 'LOW' ? 'MEDIUM' : severity;
            violationRationale = `Undeclared egress: "${key}" classified as [${category}], but application privacy scope does not declare [${category}].`;
          } else if (dest.category === 'DATA_BROKER') {
            severity = 'CRITICAL';
            violationRationale = `Data Broker Exfiltration: Personal [${category}] dispatched to known broker entity [${dest.entityName}].`;
          } else if (dest.category === 'AD_NETWORK') {
            severity = 'HIGH';
            violationRationale = `Ad Network Telemetry: User [${category}] exposed to ad attribution endpoint.`;
          } else {
            violationRationale = `Session Replay / Behavioral Egress to third party.`;
          }

          exposures.push({
            flowId: flow.id,
            destinationDomain: flow.destinationDomain,
            entityName: dest.entityName,
            dataCategory: category,
            field: key,
            valueMasked: DataClassifier.maskValue(val),
            isDeclaredInPolicy: isDeclared,
            severity,
            violationRationale
          });
        }
      }
    }

    const undeclaredCount = exposures.filter(e => !e.isDeclaredInPolicy).length;
    const criticalCount = exposures.filter(e => e.severity === 'CRITICAL').length;
    const highCount = exposures.filter(e => e.severity === 'HIGH').length;

    // Privacy Score: 100 - (critical * 25) - (high * 15) - (undeclared * 10)
    let privacyScore = 100 - (criticalCount * 25) - (highCount * 15) - (undeclaredCount * 10);
    privacyScore = Math.max(0, Math.min(100, privacyScore));

    return {
      timestamp: new Date().toISOString(),
      totalFlowsAnalyzed: flows.length,
      totalExposures: exposures.length,
      undeclaredExposuresCount: undeclaredCount,
      privacyScore,
      exposures,
      flowsByCategory
    };
  }
}
