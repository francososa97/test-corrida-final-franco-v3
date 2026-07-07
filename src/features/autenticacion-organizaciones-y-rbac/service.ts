import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import type {
  AuthResult,
  AuthToken,
  LoginInput,
  Organization,
  PublicUser,
  SignupInput,
  User,
} from './types';
import {
  EmailAlreadyExistsError,
  InvalidCredentialsError,
  ValidationError,
} from './types';

/** Abstraction over user persistence so the service stays storage-agnostic. */
export interface UserRepository {
  findByEmail(email: string): Promise<User | undefined>;
  create(user: User): Promise<User>;
}

/** Abstraction over organization persistence. */
export interface OrganizationRepository {
  create(organization: Organization): Promise<Organization>;
  findById(id: string): Promise<Organization | undefined>;
}

/** Injectable clock so timestamps are deterministic under test. */
export interface Clock {
  now(): Date;
}

const systemClock: Clock = {
  now: (): Date => new Date(),
};

// ---------------------------------------------------------------------------
// Password hashing (scrypt, no third-party dependency)
// ---------------------------------------------------------------------------

const SCRYPT_KEYLEN = 64;

export function hashPassword(plain: string): string {
  const salt = randomBytes(16);
  const derived = scryptSync(plain, salt, SCRYPT_KEYLEN);
  return `${salt.toString('hex')}:${derived.toString('hex')}`;
}

export function verifyPassword(plain: string, stored: string): boolean {
  const [saltHex, hashHex] = stored.split(':');
  if (saltHex === undefined || hashHex === undefined) {
    return false;
  }
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  const derived = scryptSync(plain, salt, expected.length);
  return expected.length === derived.length && timingSafeEqual(expected, derived);
}

// ---------------------------------------------------------------------------
// Token issuing (self-contained HS256 JWT)
// ---------------------------------------------------------------------------

export interface TokenIssuerConfig {
  secret: string;
  ttlSeconds: number;
}

interface TokenPayload {
  sub: string;
  orgId: string;
  role: User['role'];
  iat: number;
  exp: number;
}

export class JwtTokenIssuer {
  constructor(
    private readonly config: TokenIssuerConfig,
    private readonly clock: Clock = systemClock,
  ) {}

  issue(user: User): AuthToken {
    const iat = Math.floor(this.clock.now().getTime() / 1000);
    const exp = iat + this.config.ttlSeconds;
    const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload: TokenPayload = {
      sub: user.id,
      orgId: user.organizationId,
      role: user.role,
      iat,
      exp,
    };
    const encodedPayload = base64url(JSON.stringify(payload));
    const signature = this.sign(`${header}.${encodedPayload}`);
    return {
      token: `${header}.${encodedPayload}.${signature}`,
      expiresAt: new Date(exp * 1000).toISOString(),
    };
  }

  private sign(data: string): string {
    return createHmac('sha256', this.config.secret).update(data).digest('base64url');
  }
}

function base64url(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

// ---------------------------------------------------------------------------
// In-memory repositories (default wiring / tests)
// ---------------------------------------------------------------------------

export class InMemoryUserRepository implements UserRepository {
  private readonly byEmail = new Map<string, User>();

  async findByEmail(email: string): Promise<User | undefined> {
    return this.byEmail.get(email.toLowerCase());
  }

  async create(user: User): Promise<User> {
    this.byEmail.set(user.email.toLowerCase(), user);
    return user;
  }
}

export class InMemoryOrganizationRepository implements OrganizationRepository {
  private readonly byId = new Map<string, Organization>();

  async create(organization: Organization): Promise<Organization> {
    this.byId.set(organization.id, organization);
    return organization;
  }

  async findById(id: string): Promise<Organization | undefined> {
    return this.byId.get(id);
  }
}

// ---------------------------------------------------------------------------
// Auth service
// ---------------------------------------------------------------------------

export interface AuthServiceDeps {
  users: UserRepository;
  organizations: OrganizationRepository;
  tokens: JwtTokenIssuer;
  clock?: Clock;
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 8;

export class AuthService {
  private readonly users: UserRepository;
  private readonly organizations: OrganizationRepository;
  private readonly tokens: JwtTokenIssuer;
  private readonly clock: Clock;

  constructor(deps: AuthServiceDeps) {
    this.users = deps.users;
    this.organizations = deps.organizations;
    this.tokens = deps.tokens;
    this.clock = deps.clock ?? systemClock;
  }

  /**
   * Registers a new user together with a brand-new organization (the user
   * becomes its `owner`). Throws EmailAlreadyExistsError (409) on duplicates.
   */
  async signup(input: SignupInput): Promise<AuthResult> {
    const email = normalizeEmail(input.email);
    this.assertValidCredentials(email, input.password);

    const existing = await this.users.findByEmail(email);
    if (existing !== undefined) {
      throw new EmailAlreadyExistsError(email);
    }

    const createdAt = this.clock.now().toISOString();
    const organization = await this.organizations.create({
      id: generateId('org'),
      name: resolveOrganizationName(input, email),
      createdAt,
    });

    const user = await this.users.create({
      id: generateId('usr'),
      email,
      passwordHash: hashPassword(input.password),
      organizationId: organization.id,
      role: 'owner',
      createdAt,
    });

    return this.buildResult(user, organization);
  }

  /** Authenticates a user. Throws InvalidCredentialsError (401) on mismatch. */
  async login(input: LoginInput): Promise<AuthResult> {
    const email = normalizeEmail(input.email);
    const user = await this.users.findByEmail(email);
    if (user === undefined || !verifyPassword(input.password, user.passwordHash)) {
      throw new InvalidCredentialsError();
    }

    const organization = await this.organizations.findById(user.organizationId);
    if (organization === undefined) {
      // Data-integrity fallback: never leak whether the account exists.
      throw new InvalidCredentialsError();
    }

    return this.buildResult(user, organization);
  }

  private buildResult(user: User, organization: Organization): AuthResult {
    return {
      user: toPublicUser(user),
      organization,
      auth: this.tokens.issue(user),
    };
  }

  private assertValidCredentials(email: string, password: string): void {
    if (!EMAIL_PATTERN.test(email)) {
      throw new ValidationError('A valid email is required');
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      throw new ValidationError(
        `Password must be at least ${MIN_PASSWORD_LENGTH} characters long`,
      );
    }
  }
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function resolveOrganizationName(input: SignupInput, email: string): string {
  const provided = input.organizationName?.trim();
  if (provided !== undefined && provided.length > 0) {
    return provided;
  }
  const localPart = email.split('@')[0] ?? 'my';
  return `${localPart}'s organization`;
}

function toPublicUser(user: User): PublicUser {
  return {
    id: user.id,
    email: user.email,
    organizationId: user.organizationId,
    role: user.role,
    createdAt: user.createdAt,
  };
}

function generateId(prefix: string): string {
  return `${prefix}_${randomBytes(12).toString('hex')}`;
}
