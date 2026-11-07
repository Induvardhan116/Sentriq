export type AppRoute =
  | { view: 'overview' }
  | { view: 'projects' }
  | { view: 'project'; projectId: string }
  | { view: 'scan'; scanId: string; findingId?: string }
  | { view: 'findings'; findingId?: string }
  | { view: 'analytics' }
  | { view: 'repositories' }
  | { view: 'repository'; repoId: string }
  | { view: 'api-security' }
  | { view: 'cloud-security' }
  | { view: 'reports' }
  | { view: 'settings' }
  | { view: 'integrations' }
  | { view: 'workspaces' }
  | { view: 'login' }
  | { view: 'register' }
  | { view: 'forgot-password' }
  | { view: 'reset-password'; token?: string }
  | { view: 'verify-email'; token?: string }
  | { view: 'error'; message: string; submessage?: string };

/**
 * Parse the current browser location into an application route.
 * Inspects the hash fragment first (e.g. "#/scan/123", "#/projects").
 * If the hash is empty, falls back to inspecting pathname.
 */
export function parseRoute(
  hash: string = typeof window !== 'undefined' ? window.location.hash : '',
  pathname: string = typeof window !== 'undefined' ? window.location.pathname : ''
): AppRoute {
  let raw = (hash || '').replace(/^#/, '').trim();

  // If no hash route is present, check pathname fallback
  if (!raw && pathname && pathname !== '/') {
    raw = pathname.trim();
  }

  if (!raw || raw === '/') {
    return { view: 'overview' };
  }

  const [pathPart, queryPart] = raw.split('?');
  const queryParams = new URLSearchParams(queryPart || '');
  const findingId = queryParams.get('finding') || undefined;
  const token = queryParams.get('token') || undefined;

  // Split into path segments, filtering out empty strings
  const segments = pathPart.split('/').filter(Boolean);
  if (segments.length === 0) {
    return { view: 'overview' };
  }

  const first = segments[0].toLowerCase();

  if (first === 'login') {
    return { view: 'login' };
  }

  if (first === 'register' || first === 'signup') {
    return { view: 'register' };
  }

  if (first === 'forgot-password' || first === 'forgot') {
    return { view: 'forgot-password' };
  }

  if (first === 'reset-password' || first === 'reset') {
    return { view: 'reset-password', token };
  }

  if (first === 'verify-email' || first === 'verify') {
    return { view: 'verify-email', token };
  }

  if (first === 'findings' || first === 'finding') {
    const findingIdParam = segments[1] || findingId;
    return { view: 'findings', findingId: findingIdParam || undefined };
  }

  if (first === 'analytics' || first === 'risk') {
    return { view: 'analytics' };
  }

  if (first === 'api-security' || first === 'apisec' || first === 'api_security') {
    return { view: 'api-security' };
  }

  if (first === 'cloud-security' || first === 'cspm' || first === 'cloud') {
    return { view: 'cloud-security' };
  }

  if (first === 'reports' || first === 'report' || first === 'export') {
    return { view: 'reports' };
  }

  if (first === 'settings' || first === 'config' || first === 'profile') {
    return { view: 'settings' };
  }

  if (first === 'integrations' || first === 'integration' || first === 'webhooks') {
    return { view: 'integrations' };
  }

  if (first === 'workspaces' || first === 'workspace' || first === 'governance') {
    return { view: 'workspaces' };
  }

  if (first === 'repositories' || first === 'repos' || first === 'repo') {
    if (segments.length === 1) {
      return { view: 'repositories' };
    }
    const repoId = segments.slice(1).join('/').trim();
    if (!repoId) {
      return { view: 'repositories' };
    }
    return { view: 'repository', repoId };
  }

  if (first === 'overview' || first === 'dashboard') {
    return { view: 'overview' };
  }

  if (first === 'projects') {
    if (segments.length === 1) {
      return { view: 'projects' };
    }
    const projectId = segments.slice(1).join('/').trim();
    if (!projectId) {
      return {
        view: 'error',
        message: 'Missing Project ID',
        submessage: 'No project ID was provided in the URL.',
      };
    }
    return { view: 'project', projectId };
  }

  if (first === 'project') {
    if (segments.length === 1) {
      return {
        view: 'error',
        message: 'Missing Project ID',
        submessage: 'No project ID was provided in the URL.',
      };
    }
    const projectId = segments.slice(1).join('/').trim();
    if (!projectId) {
      return {
        view: 'error',
        message: 'Missing Project ID',
        submessage: 'No project ID was provided in the URL.',
      };
    }
    return { view: 'project', projectId };
  }

  if (first === 'scans' || first === 'scan') {
    if (segments.length === 1) {
      return {
        view: 'error',
        message: 'Missing Scan ID',
        submessage: 'No scan ID was provided in the URL.',
      };
    }
    const scanId = segments.slice(1).join('/').trim();
    if (!scanId) {
      return {
        view: 'error',
        message: 'Missing Scan ID',
        submessage: 'No scan ID was provided in the URL.',
      };
    }
    return { view: 'scan', scanId, findingId };
  }

  return { view: 'overview' };
}

/**
 * Format an application route into its canonical hash string.
 */
export function routeToHash(route: AppRoute): string {
  switch (route.view) {
    case 'overview':
      return '#/overview';
    case 'findings':
      return route.findingId
        ? `#/findings?finding=${encodeURIComponent(route.findingId)}`
        : '#/findings';
    case 'analytics':
      return '#/analytics';
    case 'repositories':
      return '#/repositories';
    case 'repository':
      return `#/repo/${encodeURIComponent(route.repoId)}`;
    case 'api-security':
      return '#/api-security';
    case 'cloud-security':
      return '#/cloud-security';
    case 'reports':
      return '#/reports';
    case 'settings':
      return '#/settings';
    case 'integrations':
      return '#/integrations';
    case 'workspaces':
      return '#/workspaces';
    case 'projects':
      return '#/projects';
    case 'project':
      return `#/project/${encodeURIComponent(route.projectId)}`;
    case 'scan':
      return route.findingId
        ? `#/scan/${encodeURIComponent(route.scanId)}?finding=${encodeURIComponent(route.findingId)}`
        : `#/scan/${encodeURIComponent(route.scanId)}`;
    case 'login':
      return '#/login';
    case 'register':
      return '#/register';
    case 'forgot-password':
      return '#/forgot-password';
    case 'reset-password':
      return route.token
        ? `#/reset-password?token=${encodeURIComponent(route.token)}`
        : '#/reset-password';
    case 'verify-email':
      return route.token
        ? `#/verify-email?token=${encodeURIComponent(route.token)}`
        : '#/verify-email';
    case 'error':
      return typeof window !== 'undefined' && window.location.hash
        ? window.location.hash
        : '#/projects';
  }
}

/**
 * Programmatically navigate to a new route by setting the URL hash.
 */
export function navigate(route: AppRoute, replace = false): void {
  if (typeof window === 'undefined') return;

  const hash = routeToHash(route);
  if (replace) {
    window.history.replaceState(null, '', hash);
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  } else {
    window.location.hash = hash;
  }
}
