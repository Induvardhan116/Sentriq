import { Scan } from './scan';

export interface Project {
  id: string;
  name: string;
  target_url: string;
  authorization_confirmed: boolean;
  latest_scan?: Scan | null;
  scans?: Scan[];
  created_at: string;
  updated_at: string;
}

export interface ProjectCreate {
  name: string;
  target_url: string;
  authorization_confirmed: boolean;
}
