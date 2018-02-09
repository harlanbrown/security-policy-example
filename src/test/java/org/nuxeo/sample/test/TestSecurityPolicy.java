package org.nuxeo.sample.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.nuxeo.ecm.core.api.security.Access.DENY;
import static org.nuxeo.ecm.core.api.security.Access.GRANT;
import static org.nuxeo.ecm.core.api.security.Access.UNKNOWN;
import static org.nuxeo.ecm.core.api.security.SecurityConstants.READ;

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
import org.nuxeo.ecm.core.api.impl.UserPrincipal;
import org.nuxeo.ecm.core.model.Document;
import org.nuxeo.ecm.core.model.Session;
import org.nuxeo.ecm.core.security.SecurityPolicyService;
import org.nuxeo.ecm.core.test.CoreFeature;
import org.nuxeo.ecm.core.test.annotations.Granularity;
import org.nuxeo.ecm.core.test.annotations.RepositoryConfig;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.runtime.test.NXRuntimeTestCase;
import org.nuxeo.runtime.test.runner.Deploy;
import org.nuxeo.runtime.test.runner.Features;
import org.nuxeo.runtime.test.runner.FeaturesRunner;
import org.nuxeo.runtime.test.runner.LocalDeploy;
import org.nuxeo.ecm.core.test.CoreFeature;

@RunWith(FeaturesRunner.class)
@Features(CoreFeature.class)
@RepositoryConfig(cleanup = Granularity.METHOD)
@Deploy({
    "org.nuxeo.ecm.core:OSGI-INF/SecurityService.xml"
})
@LocalDeploy({
    "org.nuxeo.sample.securitypolicy:OSGI-INF/security-policy-contrib.xml"
})
public class TestSecurityPolicy {

    static final String user = "Bubbles";

    static final Principal userPrincipal = new UserPrincipal(user, new ArrayList<>(), false, false);
    private static final Log log = LogFactory.getLog(TestSecurityPolicy.class);

    @Inject
    protected CoreSession coreSession;
    
    protected Session session;

    @Inject
    protected SecurityPolicyService service;

    @Before
    public void setUp() {
        session = ((AbstractSession) coreSession).getSession();
    }

    @Test
    public void testPolicy() throws Exception {

        String permission = READ;
        String[] permissions = { READ };

        Integer year = 2019 ;
        Calendar cal = Calendar.getInstance();
        cal.set(year, Calendar.JANUARY, 1, 0, 0, 0);
        cal.set(Calendar.MILLISECOND, 0);

        Document root = session.getRootDocument();
        Document doc = root.addChild("doc", "File");
        assertNotNull(doc);
        doc.setPropertyValue("dc:expired", cal);
        assertSame(DENY, service.checkPermission(doc, null, userPrincipal, permission, permissions, null));
    }

}
