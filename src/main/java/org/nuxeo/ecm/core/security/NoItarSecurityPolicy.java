/*
 * Copyright (c) 2006-2011 Nuxeo SA (http://nuxeo.com/) and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Harlan Brown
 */
package org.nuxeo.sample;

import java.security.Principal;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentException;
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

public class NoItarSecurityPolicy extends AbstractSecurityPolicy implements SecurityPolicy {

    // ENTER THE ITAR READERS GROUP NAME AND ITAR YES/NO FIELD HERE BEFORE COMPILING
    public static final String ITAR_READERS_GROUP = "itar_readers";

    public static final String ITAR_FIELD = "ITAR:ITAR_doc";

    private static final Log log = LogFactory.getLog(NoItarSecurityPolicy.class);

    @Override
    public Access checkPermission(Document doc, ACP mergedAcp, Principal principal, String permission,
            String[] resolvedPermissions, String[] additionalPrincipals) {

        // if document is of type FILE
        if (doc.getType().getName().equals("File")){

            try {
                // get value of ITAR field
                String s = (String) doc.getPropertyValue(ITAR_FIELD);

                // if value is not null, and is Yes
                if ( s != null && s.equals("Yes") ){
                    // and user is NOT a member of ITAR group
                    if (!((NuxeoPrincipal) principal).isMemberOf(ITAR_READERS_GROUP)){
                        // DENY access to the item
                        return Access.DENY;
                    }
                } 

            } catch (DocumentException e){
                log.error(e.toString());
            }
        }
        return Access.UNKNOWN;
    }

    @Override
    public boolean isRestrictingPermission(String permission) {
        return true;
    }

    @Override
    public boolean isExpressibleInQuery() {
        return true;
    }

    public static class NoItarTransformer implements Transformer {

        private static final long serialVersionUID = 1L;

        // Expressions for three parameters, we need to check that:
        // * document type is File
        // * ITAR value is Yes
        // * ITAR value is not null
        public static final Expression IS_FILE = new Expression(new Reference("ecm:primaryType"), Operator.EQ,
                new StringLiteral("File"));
        public static final Expression ITAR_YES = new Expression(new Reference(ITAR_FIELD), Operator.EQ,
                new StringLiteral("Yes"));
        public static final Expression ITAR_NOT_NULL = new Expression(new Reference(ITAR_FIELD), Operator.ISNOTNULL, null);

        // A SQL Query is made whenever a document listing is shown
        // This transformer changes the SQL query so that restricted documents are not shown in results
        @Override
        public SQLQuery transform(Principal principal, SQLQuery query) {

            // if user is system or Admin do nothing
            if (principal.getName().equals("system") || principal.getName().equals("Administrator")){
                return query;
            }

            WhereClause where = query.where;
            Expression expr = new Expression(IS_FILE, Operator.AND, ITAR_YES);
            expr = new Expression(expr, Operator.AND, ITAR_NOT_NULL);
            Predicate predicate;

            // a sql query can have a WHERE clause or not have a WHERE clause
            // if it does not have a WHERE clause we add our new clause using WHERE
            // if it already has a WHERE clause we add our expressions to it

            if (where == null || where.predicate == null) {
                // add WHERE NOT (ecm:primaryType = 'File' AND ITAR:ITAR_doc = 'Yes' AND ITAR:ITAR_doc is not null)
                predicate = new Predicate(expr, Operator.NOT, null);
            } else {
                // add AND NOT (ecm:primaryType = 'File' AND ITAR:ITAR_doc = 'Yes' AND ITAR:ITAR_doc is not null) to WHERE clause
                predicate = new Predicate(where.predicate, Operator.AND, new Predicate(expr, Operator.NOT, null));
            }

            SQLQuery newQuery = new SQLQuery(query.select, query.from, new WhereClause(predicate), query.groupBy,
                    query.having, query.orderBy, query.limit, query.offset);

            // to get group membership we must cast principal as a NuxeoPrincipal
            // if principal is member of ITAR_READERS_GROUP, do nothing
            // else add filters
            if (((NuxeoPrincipal) principal).isMemberOf(ITAR_READERS_GROUP)){
                return query;
            } else {
                return newQuery;
            }
        }
    }

    public static final Transformer NO_ITAR_TRANSFORMER = new NoItarTransformer();

    @Override
    public Transformer getQueryTransformer() {
        return NO_ITAR_TRANSFORMER;
    }

}
