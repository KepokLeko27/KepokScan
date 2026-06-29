export interface HeaderAnalysis {
  name: string;
  present: boolean;
  value: string | null;
  status: 'secure' | 'warning' | 'danger' | 'info';
  rating: string;
  description: string;
  recommendation: string;
}

export interface ExposureItem {
  name: string;
  url: string;
  status: 'secure' | 'warning' | 'danger';
  found: boolean;
  details: string;
  recommendation: string;
}

export interface SecurityReport {
  url: string;
  scannedAt: string;
  status: 'success' | 'error';
  statusCode: number | null;
  score: number;
  grade: string;
  summary: {
    secure: number;
    warning: number;
    danger: number;
    info: number;
    total: number;
  };
  headers: {
    'strict-transport-security': HeaderAnalysis;
    'content-security-policy': HeaderAnalysis;
    'x-frame-options': HeaderAnalysis;
    'x-content-type-options': HeaderAnalysis;
    'referrer-policy': HeaderAnalysis;
    'permissions-policy': HeaderAnalysis;
    'x-xss-protection': HeaderAnalysis;
  };
  rawHeaders: Record<string, string>;
  serverInfo: {
    server: string | null;
    poweredBy: string | null;
    ipAddress: string | null;
  };
  exposures?: ExposureItem[];
  error?: string;
}
