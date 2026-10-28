import { DataCategory } from './types.js';

export class DataClassifier {
  private static IDENTIFIER_KEYS = new Set([
    'email', 'user_email', 'phone', 'phonenumber', 'device_id', 'idfa', 'gaid',
    'advertising_id', 'ssn', 'user_id', 'ip', 'ip_address', 'username'
  ]);

  private static FINANCIAL_KEYS = new Set([
    'card_number', 'pan', 'cvv', 'cvc', 'bank_account', 'iban', 'routing_number',
    'credit_score', 'salary', 'transaction_amount'
  ]);

  private static LOCATION_KEYS = new Set([
    'lat', 'latitude', 'lon', 'lng', 'longitude', 'gps', 'coordinates', 'postal_code', 'zipcode'
  ]);

  private static BEHAVIORAL_KEYS = new Set([
    'keystrokes', 'key_log', 'mouse_moves', 'touch_events', 'dom_snapshot', 'session_replay'
  ]);

  /**
   * Classifies a key and value into a sensitive privacy category.
   */
  public static classifyField(key: string, value: any): DataCategory {
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9_]/g, '');

    if (this.FINANCIAL_KEYS.has(normalizedKey)) return 'FINANCIAL';
    if (this.BEHAVIORAL_KEYS.has(normalizedKey)) return 'BEHAVIORAL';
    if (this.LOCATION_KEYS.has(normalizedKey)) return 'LOCATION';
    if (this.IDENTIFIER_KEYS.has(normalizedKey)) return 'IDENTIFIER';

    // Pattern heuristic matching on value
    if (typeof value === 'string') {
      if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) {
        return 'IDENTIFIER';
      }
      if (/^\+?[1-9]\d{1,14}$/.test(value.replace(/[-\s()]/g, '')) && value.length >= 10) {
        return 'IDENTIFIER';
      }
      if (/^\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}$/.test(value)) {
        return 'FINANCIAL';
      }
    }

    return 'TECHNICAL';
  }

  /**
   * Masks sensitive values for secure logging and reporting.
   */
  public static maskValue(value: any): string {
    const str = String(value);
    if (str.length <= 4) return '***';
    return `${str.substring(0, 2)}***${str.substring(str.length - 2)}`;
  }
}
