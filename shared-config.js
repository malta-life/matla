// Shared runtime config for BOTH user and admin sites.
// Set this once and deploy with both frontends.
// Example: window.MATLA_SHARED_API_BASE = 'https://api.yourdomain.com';
window.MATLA_SHARED_API_BASE = window.MATLA_SHARED_API_BASE || '';

// Keep one shared state scope so both websites read/write the same dataset.
window.MATLA_SHARED_DB_SCOPE = window.MATLA_SHARED_DB_SCOPE || 'matla-life-default';

// Optional API token override (if your backend validates this header).
window.JFA_API_TOKEN = window.JFA_API_TOKEN || 'change_me_super_long_random_token';

// Runtime feature flags (can be overridden before app boot)
window.MATLA_FEATURE_FLAGS = window.MATLA_FEATURE_FLAGS || {
  enableTableToolkit: true,
  enableAuditIntegrityCheck: true,
  enableAdminActivityExport: true,
  enableAdvancedA11yLabels: true
};
