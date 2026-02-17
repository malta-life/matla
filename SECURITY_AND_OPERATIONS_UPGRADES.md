# Security & Operations Upgrades

## Implemented

1. Endpoint RBAC policy middleware with signed-session enforcement for sensitive routes.
2. Immutable audit scope strengthened with export-reason logging.
3. Sensitive-field encryption store (`encrypted_sensitive_store`) for lead/client and profile PII.
4. Session lifecycle controls:
   - refresh token rotation
   - session revoke/logout
   - session listing endpoint
   - idle timeout checks
5. SMTP outbox with retry + dead-letter flow (`smtp_outbox` + dispatcher).
6. Data quality auto-alert scanner writing to `reminder_events` for admin users.
7. Lead assignment board endpoint with:
   - FA capacity visibility
   - SLA age visibility
8. Auto-assignment logic upgraded:
   - capacity-aware balancing
   - SLA counters in response
9. Export hardening:
   - export reason requirement on backup API
   - frontend export reason capture for CSV/PDF exports
10. Test scaffolding (`node --test`) added for core hardening checks.

## New API Endpoints

- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/sessions`
- `DELETE /api/auth/sessions/:sessionId`
- `GET /api/leads/assignment-board`
- `GET /api/sensitive/:recordType/:recordKey` (admin only)

## New Environment Variables

- `SESSION_REFRESH_TOKEN_TTL_SECONDS`
- `SESSION_IDLE_TIMEOUT_SECONDS`
- `SMTP_QUEUE_RETRY_LIMIT`
- `SMTP_QUEUE_BATCH_SIZE`
- `FA_ASSIGN_MAX_PENDING_PER_FA`
- `LEAD_ASSIGN_SLA_HOURS`

