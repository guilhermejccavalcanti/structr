/**
 * Copyright (C) 2010-2018 Structr GmbH
 *
 * This file is part of Structr <http://structr.org>.
 *
 * Structr is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Structr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Structr.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.structr.bolt.index;

import org.structr.api.QueryResult;
import org.structr.api.graph.Node;
import org.structr.api.search.QueryContext;
import org.structr.api.util.QueryUtils;
import org.structr.bolt.BoltDatabaseService;
import org.structr.bolt.mapper.NodeNodeMapper;

/**
 *
 */
public class CypherNodeIndex extends AbstractCypherIndex<Node> {

	private String tenantIdentifier = null;

	public CypherNodeIndex(final BoltDatabaseService db) {
		this(db, null);
	}

	public CypherNodeIndex(final BoltDatabaseService db, final String tenantIdentifier) {

		super(db);

		this.tenantIdentifier = tenantIdentifier;
	}

	@Override
	public String getQueryPrefix(final String typeLabel, final String sourceTypeLabel, final String targetTypeLabel) {

		final StringBuilder buf = new StringBuilder("MATCH (n:NodeInterface");

		if (tenantIdentifier != null) {

			buf.append(":");
			buf.append(tenantIdentifier);
		}

		if (typeLabel != null) {

			buf.append(":");
			buf.append(typeLabel);
		}

		buf.append(")");

		return buf.toString();
	}

	@Override
	public String getQuerySuffix() {
		return " RETURN DISTINCT n";
	}

	@Override
	protected String getSecurityStatement(QueryContext context, String targetNodeType){

		StringBuilder buf                           = new StringBuilder();
		String nodeType                             = targetNodeType != null ? ":" + targetNodeType : "";
		Boolean isAnonymousUser                     = !context.isAuth();
		Boolean isAdmin                             = context.isAdmin();

		if (!isAnonymousUser && !isAdmin) {

			//Node visible to authenticated users?
			buf.append("\nOPTIONAL MATCH (node:NodeInterface")
					.append(nodeType)
					.append(")")
					.append("\n")
					.append("WHERE node.`visibleToAuthenticatedUsers` = true OR node.`visibleToPublicUsers` = true")
					.append("\n")
					.append("WITH n,collect(node) AS result_VisibleToAuthenticatedUsers")
					.append("\n")
					//Node is query user?
					.append("OPTIONAL MATCH (node:NodeInterface")
					.append(nodeType)
					.append(")")
					.append("\n")
					.append("WHERE node.id = \"").append(context.getUuid()).append("\"")
					.append("\n")
					.append("WITH n,result_VisibleToAuthenticatedUsers+collect(node) AS result_Self")
					.append("\n")
					//Query user owns node
					.append("OPTIONAL MATCH (user:NodeInterface:Principal)-[:OWNS]->(node:NodeInterface")
					.append(nodeType)
					.append(")")
					.append("\n")
					.append("WHERE user.id = \"").append(context.getUuid()).append("\"")
					.append("\n")
					.append("WITH n,result_Self+collect(node) AS result_Ownership")
					.append("\n")
					//Query user has read permission
					.append("OPTIONAL MATCH (user:NodeInterface:Principal)-[s:SECURITY]->(node:NodeInterface")
					.append(nodeType)
					.append(")")
					.append("\n")
					.append("WHERE user.id = \"").append(context.getUuid()).append("\"").append(" AND ANY(x IN s.allowed WHERE x = 'read')")
					.append("\n")
					.append("WITH n,result_Ownership+collect(node) AS result_DirectPermissionGrant")
					.append("\n")
					//Query user belongs to group that has read permission
					.append("OPTIONAL MATCH (user:NodeInterface:Principal)<-[:CONTAINS]-(group:NodeInterface:Group)	")
					.append("\n")
					.append("WHERE user.id = \"").append(context.getUuid()).append("\"")
					.append("\n")
					.append("WITH n,result_DirectPermissionGrant+collect(group) AS result_ContainedGroupGrant")
					.append("\n")
					//Query user belongs to group that owns target
					.append("OPTIONAL MATCH (user:NodeInterface:Principal)<-[:CONTAINS*]-(group:NodeInterface:Group)-[s:OWNS]->(node:NodeInterface")
					.append(nodeType)
					.append(")")
					.append("\n")
					.append("WHERE user.id = \"").append(context.getUuid()).append("\"")
					.append("\n")
					.append("WITH n,result_ContainedGroupGrant+collect(node) AS result_ContainedGroupOwns")
					.append("\n")
					//Query user belongs to nested group that has read permissions
					.append("OPTIONAL MATCH (user:NodeInterface:Principal)<-[:CONTAINS*]-(group:NodeInterface:Group)-[s:SECURITY]->(node")
					.append(nodeType)
					.append(")")
					.append("\n")
					.append("WHERE user.id = \"").append(context.getUuid()).append("\"").append(" AND ANY(x IN s.allowed WHERE x = 'read')")
					.append("\n")
					.append("WITH n,result_ContainedGroupOwns+collect(node) AS totalResult")
					.append("\n")
					.append("WITH n, totalResult as accessibleNodes\n")
					.append("WHERE n IN accessibleNodes\n");

		} else if(isAdmin){

			return "";

		} else {

			//Deal with anonymous user
			buf.append("OPTIONAL MATCH (node:NodeInterface")
					.append(nodeType)
					.append(")")
					.append("\n")
					.append("WHERE node.`visibleToPublicUsers` = true")
					.append("\n")
					.append("WITH n,collect(node) AS totalResult")
					.append("\n")
					.append("WITH n, totalResult as accessibleNodes\n")
					.append("WHERE n IN accessibleNodes\n");

		}

		return buf.toString();

	}

	@Override
	public QueryResult<Node> getResult(final PageableQuery query) {
		return QueryUtils.map(new NodeNodeMapper(db), new NodeResultStream(db, query));
	}
}
