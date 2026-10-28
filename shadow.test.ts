import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EgressFlow, DataCategory } from './types.js';
import { DataClassifier } from './data-classifier.js';
import { FlowAnalyzer } from './flow-analyzer.js';

test('DataShadow Classifier: identifies identifiers, financial, and location fields', () => {
  assert.equal(DataClassifier.classifyField('user_email', 'alice@test.com'), 'IDENTIFIER');
  assert.equal(DataClassifier.classifyField('card_number', '4111-2222-3333-4444'), 'FINANCIAL');
  assert.equal(DataClassifier.classifyField('latitude', 37.7749), 'LOCATION');
  assert.equal(DataClassifier.classifyField('session_replay', {}), 'BEHAVIORAL');
  assert.equal(DataClassifier.classifyField('screen_width', 1920), 'TECHNICAL');
});

test('DataShadow Analyzer: flags undeclared exfiltration to third parties', () => {
  const flows: EgressFlow[] = [
    {
      id: 'f1',
      timestamp: new Date().toISOString(),
      sourceModule: 'checkout.js',
      destinationDomain: 'tracker.databroker.io',
      httpMethod: 'POST',
      endpoint: '/sync',
      payload: {
        email: 'victim@user.com',
        gps: '34.05,-118.24'
      }
    }
  ];

  // Only TECHNICAL is declared in app privacy policy
  const declared = new Set<DataCategory>(['TECHNICAL']);

  const audit = FlowAnalyzer.analyzeFlows(flows, declared);
  assert.equal(audit.totalExposures, 2);
  assert.ok(audit.undeclaredExposuresCount >= 1);
  assert.ok(audit.privacyScore < 50); // Severe penalty
  assert.equal(audit.exposures[0].severity, 'CRITICAL');
});

test('DataShadow Analyzer: passes legitimate declared payment flows', () => {
  const flows: EgressFlow[] = [
    {
      id: 'f2',
      timestamp: new Date().toISOString(),
      sourceModule: 'payment.ts',
      destinationDomain: 'api.stripe.com',
      httpMethod: 'POST',
      endpoint: '/v1/charges',
      payload: {
        transaction_amount: 49.99
      }
    }
  ];

  const declared = new Set<DataCategory>(['FINANCIAL', 'TECHNICAL']);
  const audit = FlowAnalyzer.analyzeFlows(flows, declared);
  assert.equal(audit.totalExposures, 0);
  assert.equal(audit.privacyScore, 100);
});
