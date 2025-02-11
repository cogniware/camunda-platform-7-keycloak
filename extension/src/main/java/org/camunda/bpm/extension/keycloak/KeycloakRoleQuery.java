package org.camunda.bpm.extension.keycloak;

import java.util.List;

import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.identity.GroupQuery;
import org.camunda.bpm.engine.impl.GroupQueryImpl;
import org.camunda.bpm.engine.impl.Page;
import org.camunda.bpm.engine.impl.interceptor.CommandContext;
import org.camunda.bpm.engine.impl.interceptor.CommandExecutor;

/**
 * TODO: This is most likely unnecessary, we could jus KeycloakGroupQuery for Role requests aswell but call KeycloakRoleService
 * instead of KeycloakGroupService inside the identity provider
 */
public class KeycloakRoleQuery extends KeycloakGroupQuery {

	private static final long serialVersionUID = 1L;

	public KeycloakRoleQuery() {
		super();
	}

	public KeycloakRoleQuery(CommandExecutor commandExecutor) {
		super(commandExecutor);
	}

	// execute queries ////////////////////////////

	@Override
	public long executeCount(CommandContext commandContext) {
		final KeycloakIdentityProviderSession identityProvider = getKeycloakIdentityProvider(commandContext);
		return identityProvider.findRoleCountByQueryCriteria(this);
	}

	@Override
	public List<Group> executeList(CommandContext commandContext, Page page) {
		final KeycloakIdentityProviderSession identityProvider = getKeycloakIdentityProvider(commandContext);
		return identityProvider.findRoleByQueryCriteria(this);
	}

	protected KeycloakIdentityProviderSession getKeycloakIdentityProvider(CommandContext commandContext) {
		return (KeycloakIdentityProviderSession) commandContext.getReadOnlyIdentityProvider();
	}

	// unimplemented features //////////////////////////////////

	@Override
	public GroupQuery memberOfTenant(String tenantId) {
		  throw new UnsupportedOperationException("The Keycloak identity provider does currently not support tenant queries.");
	}


}
