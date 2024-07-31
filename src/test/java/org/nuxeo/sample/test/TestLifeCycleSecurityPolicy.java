package org.nuxeo.sample.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.nuxeo.ecm.core.api.security.Access.DENY;
import static org.nuxeo.ecm.core.api.security.Access.UNKNOWN;
import static org.nuxeo.ecm.core.api.security.SecurityConstants.READ;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Calendar;
import javax.inject.Inject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.nuxeo.ecm.core.api.AbstractSession;
import org.nuxeo.ecm.core.api.CloseableCoreSession;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.api.PathRef;
import org.nuxeo.ecm.core.api.impl.UserPrincipal;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.model.Session;
import org.nuxeo.ecm.core.query.sql.SQLQueryParser;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery;
import org.nuxeo.ecm.core.query.sql.model.SQLQuery.Transformer;
import org.nuxeo.ecm.core.security.SecurityPolicyService;
import org.nuxeo.ecm.core.test.CoreFeature;
import org.nuxeo.ecm.core.test.annotations.Granularity;
import org.nuxeo.ecm.core.test.annotations.RepositoryConfig;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.runtime.test.runner.LocalDeploy;
import org.nuxeo.sample.LifeCycleSecurityPolicy.LifeCycleTransformer;

@RunWith(FeaturesRunner.class)
@Features(CoreFeature.class)
@RepositoryConfig(cleanup = Granularity.METHOD)
@Deploy({
	"org.nuxeo.ecm.platform.content.template"
})
@LocalDeploy({
    "org.nuxeo.sample.securitypolicy:OSGI-INF/security-policy-contrib.xml"
})
public class TestLifeCycleSecurityPolicy {

    static final String members = "members";
	static final NuxeoPrincipal membersPrincipal = new UserPrincipal(members, new ArrayList<>(), false, false);
	
    protected DocumentModel doc;
    protected DocumentModel doc2;

    @Inject
    protected SecurityPolicyService service;    
    
    @Inject
    protected CoreSession coreSession;

    @Inject
    protected CoreFeature coreFeature;

    @Before
    public void setUp() {

    	doc = coreSession.createDocumentModel("/", "approved", "File");
    	doc = coreSession.createDocument(doc);
        // follow lifecycle transition
        coreSession.followTransition(new PathRef("/approved"), "approve");
    	
    	doc2 = coreSession.createDocumentModel("/", "project", "File");
    	doc2 = coreSession.createDocument(doc2);
    	
    	coreSession.save();
    }
    
    @Test
    public void testQuery() throws Exception {
    	
        try (CloseableCoreSession coreSession = coreFeature.openCoreSession("Administrator")) {
        	assertEquals(2,coreSession.query("SELECT * FROM File").size());
        }
        
        try (CloseableCoreSession coreSession = coreFeature.openCoreSession("members")) {
        	assertEquals(1,coreSession.query("SELECT * FROM File").size());
        }
    	
    }
    
    @Test
    public void testCheckPermission() throws Exception {
    	
    	String permission = READ;
        String[] permissions = { READ };

        try (CloseableCoreSession coreSession = coreFeature.openCoreSession("members")) {
        	Session documentSession = ((AbstractSession) coreSession).getSession();

        	Document d = documentSession.getDocumentByUUID(doc.getId());
        	assertSame(UNKNOWN, service.checkPermission(d, null, membersPrincipal, permission, permissions, null));
            
        	Document d2 = documentSession.getDocumentByUUID(doc2.getId());
        	assertSame(DENY, service.checkPermission(d2, null, membersPrincipal, permission, permissions, null));
        }
        
    }
    
    @Test
    public void testTransformer() throws Exception {
    	
    	Transformer t = new LifeCycleTransformer();
    	SQLQuery p = SQLQueryParser.parse("SELECT * FROM File");
    	SQLQuery s = t.transform(membersPrincipal, p);
    	assertTrue(s.toString().contains("ecm:currentLifeCycleState = 'approved'")); 
    	
    }
}
