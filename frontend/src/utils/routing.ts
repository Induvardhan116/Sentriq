export type AppRoute =
  | { view: 'overview' }
  | { view: 'projects' }
  | { view: 'project'; projectId: string }
  | { view: 'scan'; scanId: string; findingId?: string }
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

  // Split into path segments, filtering out empty strings
  const segments = pathPart.split('/').filter(Boolean);
  if (segments.length === 0) {
    return { view: 'overview' };
  }

  const first = segments[0].toLowerCase();

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
    case 'projects':
      return '#/projects';
    case 'project':
      return `#/project/${encodeURIComponent(route.projectId)}`;
    case 'scan':
      return route.findingId
        ? `#/scan/${encodeURIComponent(route.scanId)}?finding=${encodeURIComponent(route.findingId)}`
        : `#/scan/${encodeURIComponent(route.scanId)}`;
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
