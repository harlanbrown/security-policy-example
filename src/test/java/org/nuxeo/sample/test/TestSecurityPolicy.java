package org.nuxeo.sample.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.nuxeo.ecm.core.api.security.Access.DENY;
import static org.nuxeo.ecm.core.api.security.Access.GRANT;
import static org.nuxeo.ecm.core.api.security.Access.UNKNOWN;
import static org.nuxeo.ecm.core.api.security.SecurityConstants.READ;
import static org.nuxeo.ecm.core.api.security.SecurityConstants.ADMINISTRATOR;
import static org.nuxeo.ecm.core.api.security.SecurityConstants.ANONYMOUS;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Calendar;
import javax.inject.Inject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.nuxeo.ecm.core.api.AbstractSession;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.PathRef;
import org.nuxeo.ecm.core.api.impl.UserPrincipal;
import org.nuxeo.ecm.core.api.security.Access;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.model.Session;
import org.nuxeo.ecm.core.security.SecurityPolicyService;
import org.nuxeo.ecm.core.test.CoreFeature;
import org.nuxeo.ecm.core.test.annotations.Granularity;
import org.nuxeo.ecm.core.test.annotations.RepositoryConfig;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.runtime.test.runner.LocalDeploy;

@RunWith(FeaturesRunner.class)
@Features(CoreFeature.class)
@RepositoryConfig(cleanup = Granularity.METHOD)
@Deploy({
	"org.nuxeo.ecm.platform.content.template"
})
@LocalDeploy({
    "org.nuxeo.sample.securitypolicy:OSGI-INF/security-policy-contrib.xml"
})
public class TestSecurityPolicy {

    static final String user = "Bubbles";
	static final Principal userPrincipal = new UserPrincipal(user, new ArrayList<>(), false, false);

    private static final Log log = LogFactory.getLog(TestSecurityPolicy.class);
    
    protected DocumentModel doc;
    protected DocumentModel doc2;

    @Inject
    protected SecurityPolicyService service;    
    
    @Inject
    protected CoreSession coreSession;

    @Inject
    protected CoreFeature coreFeature;

    @Test
    public void testPolicy() throws Exception {
    	
    	try (CoreSession coreSession = coreFeature.openCoreSession(ADMINISTRATOR)) {

    		Integer year = 2019 ;
	        Calendar cal = Calendar.getInstance();
	        cal.set(year, Calendar.JANUARY, 1, 0, 0, 0);
	        cal.set(Calendar.MILLISECOND, 0);
	    	doc = coreSession.createDocumentModel("/", "2019", "File");
	    	doc = coreSession.createDocument(doc);
	    	doc.setPropertyValue("dc:expired", cal);	  
	    	
	    	year = 2011;
	        cal.set(year, Calendar.JANUARY, 1, 0, 0, 0);
	        cal.set(Calendar.MILLISECOND, 0);
	    	doc2 = coreSession.createDocumentModel("/", "2011", "File");
	    	doc2 = coreSession.createDocument(doc2);
	    	doc2.setPropertyValue("dc:expired", cal);

	    	coreSession.save();
        }
    	
    	String permission = READ;
        String[] permissions = { READ };

        try (CoreSession coreSession = coreFeature.openCoreSession(ANONYMOUS)) {
        	Session documentSession = ((AbstractSession) coreSession).getSession();

        	Document d = documentSession.getDocumentByUUID(doc.getId());
        	assertNotNull(d.getPropertyValue("dc:expired"));
        	//assertSame(UNKNOWN, service.checkPermission(d, null, userPrincipal, permission, permissions, null));
            
        	//Document d2 = documentSession.getDocumentByUUID(doc2.getId());
        	//assertNotNull(d2.getPropertyValue("dc:expired"));
        	//assertSame(DENY, service.checkPermission(d2, null, userPrincipal, permission, permissions, null));

        }
    }
}
