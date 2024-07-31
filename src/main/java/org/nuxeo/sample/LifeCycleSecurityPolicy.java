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

public class LifeCycleSecurityPolicy extends AbstractSecurityPolicy implements SecurityPolicy {

    @Override
    public Access checkPermission(Document doc, ACP mergedAcp, NuxeoPrincipal principal, String permission,
            String[] resolvedPermissions, String[] additionalPrincipals) {

        String lifeCycle = doc.getLifeCycleState();

        if ( lifeCycle != null ) {
            // if current lifecycle state is NOT approved
            if ( !lifeCycle.equals("approved") ) {
                // DENY access to the item
                return Access.DENY;
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

    public static class LifeCycleTransformer implements Transformer {

        private static final long serialVersionUID = 1L;

        // Expressions, we need to check that:
        // * current lifecycle state is approved
        public static final Expression APPROVED = new Expression(new Reference("ecm:currentLifeCycleState"), Operator.EQ, new StringLiteral("approved")); 

        // A SQL Query is made whenever a document listing is shown
        // This transformer changes the SQL query so that restricted documents are not shown in results
        @Override
        public SQLQuery transform(NuxeoPrincipal principal, SQLQuery query) {

            // if user is system or Admin do nothing
            if (principal.getName().equals("system") || principal.getName().equals("Administrator")){
                return query;
            }

            WhereClause where = query.where;
            Predicate predicate;

            // a sql query can have a WHERE clause or not have a WHERE clause
            // if it does not have a WHERE clause we add our new clause using WHERE
            // if it already has a WHERE clause we add our expressions to it

            if (where == null || where.predicate == null) {
                // add WHERE ecm lifecycle is approved
                predicate = new Predicate(new Reference("ecm:currentLifeCycleState"), Operator.EQ, new StringLiteral("approved"));
            } else {
                // add AND ecm lifecycle is approved to WHERE clause
                predicate = new Predicate(where.predicate, Operator.AND, new Predicate(new Reference("ecm:currentLifeCycleState"), Operator.EQ, new StringLiteral("approved")));
            }

            return new SQLQuery(query.select, query.from, new WhereClause(predicate), query.groupBy, query.having, query.orderBy, query.limit, query.offset);

        }
    }

    public static final Transformer LIFECYCLE_TRANSFORMER = new LifeCycleTransformer();

    @Override
    public Transformer getQueryTransformer(String repositoryName) {
        return LIFECYCLE_TRANSFORMER;
    }

}
