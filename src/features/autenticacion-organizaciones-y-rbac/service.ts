// Capa de servicio para GET /‹resource› multi-tenant.
//
// El tenant activo SIEMPRE proviene del AuthContext (derivado del token), nunca
// del payload del cliente. Esto satisface el acceptance criteria:
//   Usuario del tenant A -> GET /‹resource› devuelve solo filas org_id = A.
//   Test cruzado tenant B -> 0 resultados ajenos.

import { TenantAwareRepository } from './repository';
import type { AuthContext, Resource } from './types';

export class ResourceService {
  constructor(private readonly repo: TenantAwareRepository<Resource>) {}

  /**
   * Handler de GET /‹resource›. Ignora cualquier organization_id externo y usa
   * exclusivamente el del contexto autenticado.
   */
  async listResources(auth: AuthContext): Promise<readonly Resource[]> {
    return this.repo.list(auth.organizationId);
  }

  /** GET /‹resource›/:id — devuelve null (=> 404) si la fila es de otro tenant. */
  async getResource(auth: AuthContext, id: string): Promise<Resource | null> {
    return this.repo.getById(auth.organizationId, id);
  }

  /** POST /‹resource› — el organization_id se fuerza desde el token. */
  async createResource(
    auth: AuthContext,
    input: Omit<Resource, 'organizationId'>,
  ): Promise<Resource> {
    return this.repo.create(auth.organizationId, {
      ...input,
      organizationId: auth.organizationId,
    });
  }
}

export const createResourceService = (
  repo: TenantAwareRepository<Resource>,
): ResourceService => new ResourceService(repo);
