package org.camunda.bpm.extension.keycloak;

import static org.camunda.bpm.extension.keycloak.json.JsonUtil.getJsonObjectAtIndex;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.getJsonString;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.parseAsJsonArray;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.parseAsJsonObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.camunda.bpm.engine.authorization.Groups;
import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.impl.identity.IdentityProviderException;
import org.camunda.bpm.engine.impl.persistence.entity.GroupEntity;
import org.camunda.bpm.extension.keycloak.json.JsonException;
import org.camunda.bpm.extension.keycloak.rest.KeycloakRestTemplate;
import org.camunda.bpm.extension.keycloak.util.KeycloakPluginLogger;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class KeycloakRoleService extends KeycloakGroupService {
// public class KeycloakRoleService extends KeycloakServiceBase {
    
    /**
	 * Default constructor.
	 * 
	 * @param keycloakConfiguration the Keycloak configuration
	 * @param restTemplate REST template
	 * @param keycloakContextProvider Keycloak context provider
	 */
	public KeycloakRoleService(KeycloakConfiguration keycloakConfiguration,
			KeycloakRestTemplate restTemplate, KeycloakContextProvider keycloakContextProvider) {
		super(keycloakConfiguration, restTemplate, keycloakContextProvider);
	}


    
	public String getKeycloakAdminGroupId(String configuredAdminGroupName) {
		return null;
	}



	/**
	 * Requests groups of a specific user.
	 * @param query the group query - including a userId criteria
	 * @return list of matching groups
	 */
	public List<Group> requestGroupsByUserId(CacheableKeycloakGroupQuery query) {
		String userId = query.getUserId();
		List<Group> groupList = new ArrayList<>();

		try {
			String roleSearch = "/role-mappings";
			// TODO make this configurable or something ?
			roleSearch += "/realm/composite";


			//  get Keycloak specific userID
			String keyCloakID;
			try {
				keyCloakID = getKeycloakUserID(userId);
			} catch (KeycloakUserNotFoundException e) {
				// user not found: empty search result
				return Collections.emptyList();
			}

			// get roles of this user
			ResponseEntity<String> response = restTemplate.exchange(
					keycloakConfiguration.getKeycloakAdminUrl() + "/users/" + keyCloakID + roleSearch + "?max=" + getMaxQueryResultSize(), 
					HttpMethod.GET, String.class);
			if (!response.getStatusCode().equals(HttpStatus.OK)) {
				throw new IdentityProviderException(
						"Unable to read user roles from " + keycloakConfiguration.getKeycloakAdminUrl()
								+ ": HTTP status code " + response.getStatusCodeValue());
			}

			JsonArray searchResult;
			// TODO: pro /role-mappings/realm/composite vrati API JSONArray ale pro jen /role-mappings vraci JSONobject
			// JsonObject realmMappings = parseAsJsonObject(response.getBody());
			// searchResult = realmMappings.getAsJsonArray("realmMappings");

			searchResult = parseAsJsonArray(response.getBody());
			for (int i = 0; i < searchResult.size(); i++) {
				groupList.add(transformRole(getJsonObjectAtIndex(searchResult, i)));
			}

		} catch (HttpClientErrorException hcee) {
			// if userID is unknown server answers with HTTP 404 not found
			if (hcee.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
				return Collections.emptyList();
			}
			throw hcee;
		} catch (RestClientException | JsonException rce) {
			throw new IdentityProviderException("Unable to query groups of user " + userId, rce);
		}

		return groupList;
	}


	/**
	 * Requests groups.
	 * @param query the group query - not including a userId criteria
	 * @return list of matching groups
	 */
	public List<Group> requestGroupsWithoutUserId(CacheableKeycloakGroupQuery query) {
		List<Group> groupList = new ArrayList<>();

		try {
			// get groups according to search criteria
			ResponseEntity<String> response;

			if (StringUtils.hasLength(query.getId())) {
				response = requestRoleById(query.getId());
			} else if (query.getIds() != null && query.getIds().length == 1) {
				response = requestRoleById(query.getIds()[0]);
			} else {
				String groupFilter = createRoleSearchFilter(query); // only pre-filter of names possible
				response = restTemplate.exchange(keycloakConfiguration.getKeycloakAdminUrl() + "/roles" + groupFilter, HttpMethod.GET, String.class);
			}
			if (!response.getStatusCode().equals(HttpStatus.OK)) {
				throw new IdentityProviderException(
						"Unable to read groups from " + keycloakConfiguration.getKeycloakAdminUrl()
								+ ": HTTP status code " + response.getStatusCodeValue());
			}

			// JsonArray searchResult;
			// if (StringUtils.hasLength(query.getId())) {
			// 	searchResult = parseAsJsonArray(response.getBody());
			// } else {
			// 	// for non ID queries search in subgroups as well
			// 	searchResult = flattenSubGroups(parseAsJsonArray(response.getBody()), new JsonArray());
			// }
			JsonArray searchResult = parseAsJsonArray(response.getBody());
			for (int i = 0; i < searchResult.size(); i++) {
				// System.out.println("res: " + searchResult);
				groupList.add(transformRole(getJsonObjectAtIndex(searchResult, i)));
			}

		} catch (RestClientException | JsonException rce) {
			throw new IdentityProviderException("Unable to query groups", rce);
		}

		return groupList;
	}



	/**
	 * Requests data of single group.
	 * @param groupId the ID of the requested group
	 * @return response consisting of a list containing the one group
	 * @throws RestClientException
	 */
	private ResponseEntity<String> requestRoleById(String roleId) throws RestClientException {
		try {
			String roleSearch;
			roleSearch = "/roles-by-id/" + roleId;
			// roleSearch = "/roles/" + roleId; // tohle chce myslim role name ?? idk

			ResponseEntity<String> response = restTemplate.exchange(
					keycloakConfiguration.getKeycloakAdminUrl() + roleSearch, HttpMethod.GET, String.class);
			String result = "[" + response.getBody() + "]";
			return new ResponseEntity<String>(result, response.getHeaders(), response.getStatusCode());
		} catch (HttpClientErrorException hcee) {
			if (hcee.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
				String result = "[]";
				return new ResponseEntity<String>(result, HttpStatus.OK);
			}
			throw hcee;
		}
	}
	

		/**
	 * Creates an Keycloak group search filter query
	 * @param query the group query
	 * @return request query
	 */
	private String createRoleSearchFilter(CacheableKeycloakGroupQuery query) {
		StringBuilder filter = new StringBuilder();
		boolean hasSearch = false;
		if (StringUtils.hasLength(query.getName())) {
			hasSearch = true;
			addArgument(filter, "search", query.getName());
		}
		if (StringUtils.hasLength(query.getNameLike())) {
			hasSearch = true;
			addArgument(filter, "search", query.getNameLike().replaceAll("[%,\\*]", ""));
		}
		addArgument(filter, "max", getMaxQueryResultSize());
		if (!hasSearch && keycloakConfiguration.isEnforceSubgroupsInGroupQuery()) {
			// fix: include subgroups in query result for Keycloak >= 23
			addArgument(filter, "q", ":");
		}
		if (filter.length() > 0) {
			filter.insert(0, "?");
			String result = filter.toString();
			KeycloakPluginLogger.INSTANCE.groupQueryFilter(result);
			return result;
		}
		return "";
	}

		
	/**
	 * Maps a Keycloak JSON result to a Group object
	 * @param result the Keycloak JSON result
	 * @return the Group object
	 * @throws JsonException in case of errors
	 */
	private GroupEntity transformRole(JsonObject result) throws JsonException {
		GroupEntity group = new GroupEntity();
		group.setId(getJsonString(result, "id"));
		group.setName(getJsonString(result, "name"));
		
		if (isSystemGroup(result)) {
			group.setType(Groups.GROUP_TYPE_SYSTEM);
		} else {
			group.setType(Groups.GROUP_TYPE_WORKFLOW);
		}
		return group;
	}

}
