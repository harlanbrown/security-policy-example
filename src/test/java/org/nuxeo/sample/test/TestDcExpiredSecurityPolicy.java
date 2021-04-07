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
import org.nuxeo.sample.DcExpiredSecurityPolicy.DcExpiredTransformer;

@RunWith(FeaturesRunner.class)
@Features(CoreFeature.class)
@RepositoryConfig(cleanup = Granularity.METHOD)
@Deploy({
	"org.nuxeo.ecm.platform.content.template"
})
@LocalDeploy({
    "org.nuxeo.sample.securitypolicy:OSGI-INF/security-policy-contrib.xml"
})
public class TestDcExpiredSecurityPolicy {

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

    	Calendar cal = Calendar.getInstance();
        cal.set(2050, Calendar.JANUARY, 1, 0, 0, 0);
        cal.set(Calendar.MILLISECOND, 0);
    	doc = coreSession.createDocumentModel("/", "2050", "File");
    	doc.setPropertyValue("dc:expired", cal);	  
    	doc = coreSession.createDocument(doc);
    	
        Calendar cal2 = Calendar.getInstance();
        cal2.set(2010, Calendar.JANUARY, 1, 0, 0, 0);
        cal2.set(Calendar.MILLISECOND, 0);
    	doc2 = coreSession.createDocumentModel("/", "2010", "File");
    	doc2.setPropertyValue("dc:expired", cal2);
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
    	
    	Transformer t = new DcExpiredTransformer();
    	SQLQuery p = SQLQueryParser.parse("SELECT * FROM File");
    	SQLQuery s = t.transform(membersPrincipal, p);
    	assertTrue(s.toString().contains("WHERE NOT dc:expired < TIMESTAMP"));
    	assertTrue(s.toString().contains("AND dc:expired IS NOT NULL"));
    	
    }
}
