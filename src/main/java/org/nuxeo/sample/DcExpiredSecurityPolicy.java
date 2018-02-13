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
import java.util.Calendar;

import javax.mail.Session;

import org.joda.time.DateTime;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.nuxeo.ecm.core.api.security.ACP;
import org.nuxeo.ecm.core.api.security.Access;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.query.sql.model.Expression;
import org.nuxeo.ecm.core.query.sql.model.Operator;
import org.nuxeo.ecm.core.query.sql.model.Predicate;
import org.nuxeo.ecm.core.query.sql.model.Reference;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery.Transformer;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery;
import org.nuxeo.ecm.core.query.sql.model.DateLiteral;
import org.nuxeo.ecm.core.query.sql.model.WhereClause;
import org.nuxeo.ecm.core.security.AbstractSecurityPolicy;
import org.nuxeo.ecm.core.security.SecurityPolicy;

public class DcExpiredSecurityPolicy extends AbstractSecurityPolicy implements SecurityPolicy {

    public static final String DC_EXPIRED_FIELD = "dc:expired";

    private static final Log log = LogFactory.getLog(DcExpiredSecurityPolicy.class);

    @Override
    public Access checkPermission(Document doc, ACP mergedAcp, Principal principal, String permission,
            String[] resolvedPermissions, String[] additionalPrincipals) {
    	
        Calendar expired = (Calendar) doc.getPropertyValue(DC_EXPIRED_FIELD);
        Calendar now = Calendar.getInstance();

        if ( expired != null ) {
            // if value of dc:expired field is before now
            if (expired.before(now)) {
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

    public static class DcExpiredTransformer implements Transformer {

        private static final long serialVersionUID = 1L;

        // Expressions for two parameters, we need to check that:
        // * dc:expired value is less than todays date
        // * dc:expired value is not null
        public static final Expression EXPIRED = new Expression(new Reference(DC_EXPIRED_FIELD), Operator.LT, new DateLiteral(new DateTime())); 
        public static final Expression DC_EXPIRED_NOT_NULL = new Expression(new Reference(DC_EXPIRED_FIELD), Operator.ISNOTNULL, null);

        // A SQL Query is made whenever a document listing is shown
        // This transformer changes the SQL query so that restricted documents are not shown in results
        @Override
        public SQLQuery transform(Principal principal, SQLQuery query) {

            // if user is system or Admin do nothing
            if (principal.getName().equals("system") || principal.getName().equals("Administrator")){
                return query;
            }

            WhereClause where = query.where;
            Expression expr = new Expression(EXPIRED, Operator.AND, DC_EXPIRED_NOT_NULL);
            Predicate predicate;

            // a sql query can have a WHERE clause or not have a WHERE clause
            // if it does not have a WHERE clause we add our new clause using WHERE
            // if it already has a WHERE clause we add our expressions to it

            if (where == null || where.predicate == null) {
                // add WHERE NOT (dc:expired < today AND dc:expired is not null)
                predicate = new Predicate(expr, Operator.NOT, null);
            } else {
                // add AND NOT (dc:expired < today AND dc:expired is not null) to WHERE clause
                predicate = new Predicate(where.predicate, Operator.AND, new Predicate(expr, Operator.NOT, null));
            }

            return new SQLQuery(query.select, query.from, new WhereClause(predicate), query.groupBy, query.having, query.orderBy, query.limit, query.offset);

        }
    }

    public static final Transformer DC_EXPIRED_TRANSFORMER = new DcExpiredTransformer();

    @Override
    public Transformer getQueryTransformer(String repositoryName) {
        return DC_EXPIRED_TRANSFORMER;
    }

}
