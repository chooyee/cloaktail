// Sidebar navigation of the signed-in portal and the admin console, grouped into labelled sections.
const PORTAL = [
  { label: 'Workspace', links: [
    { href: '/', label: 'Dashboard', icon: 'dashboard', perms: ['dashboard.view'] },
    { href: '/apps', label: 'Applications', icon: 'apps', perms: ['apps.own', 'apps.view_all'] },
    { href: '/test-users', label: 'Test users', icon: 'testUser', perms: ['apps.own'] },
  ] },
  { label: 'Tools', links: [
    { href: '/tools/certificate', label: 'Certificates', icon: 'certificate', perms: ['apps.own'] },
    { href: '/tools/decode', label: 'Decoders', icon: 'decoder', perms: [] },
  ] },
  { label: 'Administration', links: [
    { href: '/users', label: 'Users', icon: 'users', perms: ['users.view'] },
    { href: '/roles', label: 'Roles', icon: 'shield', perms: ['roles.view'] },
  ] },
  { label: 'Help', links: [
    { href: '/guide', label: 'Guide', icon: 'book', perms: [] },
    { href: '/troubleshooting', label: 'Troubleshooting', icon: 'lifebuoy', perms: [] },
  ] },
];

// "console" links are hidden while the administrator must change their password.
const ADMIN = [
  { label: 'Configuration', links: [
    { href: '/admin/keycloak', label: 'Keycloak profiles', icon: 'server', perms: ['console'] },
  ] },
  { label: 'Access', links: [
    { href: '/admin/accounts', label: 'Administrators', icon: 'user', perms: ['console'] },
    { href: '/admin/password', label: 'Change password', icon: 'key', perms: [] },
  ] },
];

const isActive = (href, path) => (href === '/' ? path === '/' : path === href || path.startsWith(`${href}/`));

// Layout of the current page: `shell` (sidebar layout) for signed-in users and the admin console,
// the visible nav groups, and the group and link the current page belongs to.
export function navigation({ user, admin, path, can }) {
  const adminArea = Boolean(admin) && path.startsWith('/admin');
  const shell = Boolean(user) || adminArea;
  if (!shell) return { shell, adminArea, groups: [] };
  const allowed = adminArea ? (perm) => perm !== 'console' || !admin.mustChangePassword : can;
  const groups = (adminArea ? ADMIN : PORTAL)
    .map((g) => ({
      ...g,
      links: g.links
        .filter((l) => !l.perms.length || l.perms.some(allowed))
        .map((l) => ({ ...l, active: isActive(l.href, path) })),
    }))
    .filter((g) => g.links.length);
  const group = groups.find((g) => g.links.some((l) => l.active)) || null;
  return { shell, adminArea, groups, group, link: group?.links.find((l) => l.active) || null };
}
