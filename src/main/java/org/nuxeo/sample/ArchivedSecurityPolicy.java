/*
 * Copyright (c) 2006-2018 Nuxeo SA (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Harlan Brown
 */

package org.nuxeo.sample;

import java.security.Principal;

import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.api.security.ACP;
import org.nuxeo.ecm.core.api.security.Access;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.query.sql.model.Expression;
import org.nuxeo.ecm.core.query.sql.model.Operator;
import org.nuxeo.ecm.core.query.sql.model.Predicate;
import org.nuxeo.ecm.core.query.sql.model.Reference;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery.Transformer;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery;
import org.nuxeo.ecm.core.query.sql.model.StringLiteral;
import org.nuxeo.ecm.core.query.sql.model.WhereClause;
import org.nuxeo.ecm.core.security.AbstractSecurityPolicy;
import org.nuxeo.ecm.core.security.SecurityPolicy;

public class ArchivedSecurityPolicy extends AbstractSecurityPolicy implements SecurityPolicy {

    @Override
    public Access checkPermission(Document doc, ACP mergedAcp, NuxeoPrincipal principal, String permission, String[] resolvedPermissions, String[] additionalPrincipals) {

        String lifeCycle = doc.getLifeCycleState();

        if ( doc.getType().getName().equals("CustomFile") ) {
            if ( lifeCycle != null ) {
                // if current lifecycle state is NOT archived
                if ( !lifeCycle.equals("archived") ) {
                    // DENY access to the item
                    return Access.DENY;
                }
            }
        }
        return Access.UNKNOWN;
    }

    @Override
    public boolean isRestrictingPermission(String permission) {
        return true;
    }

    @Override
    public boolean isExpressibleInQuery(String repositoryName) {
        return true;
    }

    public static class ArchivedTransformer implements Transformer {

        private static final long serialVersionUID = 1L;

        // Expressions, we need to check that:
        // * document type is CustomFile
        // * current lifecycle state is NOT archived (we're allowed to see the archived ones)
        public static final Expression IS_FILE = new Expression(new Reference("ecm:primaryType"), Operator.EQ, new StringLiteral("CustomFile"));
        public static final Expression ARCHIVED = new Expression(new Reference("ecm:currentLifeCycleState"), Operator.NOTEQ, new StringLiteral("archived")); 

        // A SQL Query is made whenever a document listing is shown
        // This transformer changes the SQL query so that restricted documents are not shown in results
        @Override
        public SQLQuery transform(NuxeoPrincipal principal, SQLQuery query) {

            // if user is system or Admin do nothing
            if (principal.getName().equals("system") || principal.getName().equals("Administrator")){
                return query;
            }

            WhereClause where = query.where;
            Expression expr = new Expression(IS_FILE, Operator.AND, ARCHIVED);
            Predicate predicate;

            // a sql query can have a WHERE clause or not have a WHERE clause
            // if it does not have a WHERE clause we add our new clause using WHERE
            // if it already has a WHERE clause we add our expressions to it

            // in this case we want to filter (don't return) files that are not archived

            if (where == null || where.predicate == null) {
                // add WHERE NOT primary type is File and ecm lifecycle not archived
                predicate = new Predicate(expr, Operator.NOT, null);
            } else {
                // add AND NOT primary type is File and ecm lifecycle not archived to WHERE clause
                predicate = new Predicate(where.predicate, Operator.AND, new Predicate(expr, Operator.NOT, null));
            }

            return new SQLQuery(query.select, query.from, new WhereClause(predicate), query.groupBy, query.having, query.orderBy, query.limit, query.offset);

        }
    }

    public static final Transformer ARCHIVED_TRANSFORMER = new ArchivedTransformer();

    @Override
    public Transformer getQueryTransformer(String repositoryName) {
        return ARCHIVED_TRANSFORMER;
    }

}
