// RBAC core: roles, permissions and authorization decisions.
// TypeScript strict — no `any`, explicit types throughout.

/** Roles a membership can hold within an organization. */
export type Role = 'member' | 'admin' | 'owner';

/** HTTP methods considered mutable (state-changing). */
export type MutableMethod = 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** All HTTP methods this module reasons about. */
export type HttpMethod = 'GET' | 'HEAD' | 'OPTIONS' | MutableMethod;

/** Set of methods that mutate resources and therefore require elevated roles. */
const MUTABLE_METHODS: ReadonlySet<HttpMethod> = new Set<HttpMethod>([
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
]);

/** Roles allowed to perform mutations on a resource. */
const MUTATING_ROLES: ReadonlySet<Role> = new Set<Role>(['admin', 'owner']);

/** Ordered privilege ranking (higher index == more privilege). */
const ROLE_RANK: Readonly<Record<Role, number>> = {
  member: 0,
  admin: 1,
  owner: 2,
};

/** A user's membership context within a single organization. */
export interface Membership {
  readonly userId: string;
  readonly organizationId: string;
  readonly role: Role;
}

/** Outcome of an authorization check. */
export interface AuthorizationResult {
  readonly allowed: boolean;
  /** HTTP status the caller should return: 403 when denied, undefined when allowed. */
  readonly status?: 403;
  readonly reason?: string;
}

/** True when the given HTTP method mutates server state. */
export function isMutableMethod(method: string): method is MutableMethod {
  return MUTABLE_METHODS.has(method.toUpperCase() as HttpMethod);
}

/** True when `role` is at least as privileged as `required`. */
export function roleAtLeast(role: Role, required: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[required];
}

/** True when `role` may perform mutations (admin or owner). */
export function canMutate(role: Role): boolean {
  return MUTATING_ROLES.has(role);
}

/**
 * Core authorization decision for a request against a resource.
 *
 * Rule (E1-T3): mutable methods (POST/PUT/PATCH/DELETE) require admin or owner.
 * `member` is denied with 403. Non-mutable methods are allowed for any role.
 */
export function authorize(
  method: string,
  membership: Membership | null | undefined,
): AuthorizationResult {
  if (!membership) {
    return {
      allowed: false,
      status: 403,
      reason: 'No membership in the target organization',
    };
  }

  if (!isMutableMethod(method)) {
    return { allowed: true };
  }

  if (canMutate(membership.role)) {
    return { allowed: true };
  }

  return {
    allowed: false,
    status: 403,
    reason: `Role "${membership.role}" cannot perform ${method.toUpperCase()} on this resource`,
  };
}
