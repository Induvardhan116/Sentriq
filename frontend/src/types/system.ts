export interface SystemHealth {
  status: 'healthy' | 'degraded';
  database: 'connected' | 'disconnected';
  app_name: string;
  version: string;
  environment: string;
  timestamp: string;
}
