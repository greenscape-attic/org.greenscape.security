package org.greenscape.security;

import java.util.Map;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.Ini.Section;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.env.DefaultWebEnvironment;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.filter.session.NoSessionCreationFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.greenscape.core.ModelResource;
import org.greenscape.core.Resource;
import org.greenscape.core.ResourceEvent;
import org.greenscape.core.ResourceRegistry;
import org.greenscape.core.ResourceType;
import org.greenscape.core.WebletResource;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.event.Event;
import org.osgi.service.event.EventConstants;
import org.osgi.service.event.EventHandler;

@Component(configurationPolicy = ConfigurationPolicy.REQUIRE, configurationPid = SecurityEnvironment.CONFIG_PID, property = {
		EventConstants.EVENT_TOPIC + "=" + ResourceRegistry.TOPIC_RESOURCE_REGISTERED,
		EventConstants.EVENT_TOPIC + "=" + ResourceRegistry.TOPIC_RESOURCE_MODIFIED,
		EventConstants.EVENT_TOPIC + "=" + ResourceRegistry.TOPIC_RESOURCE_UNREGISTERED })
public class SecurityEnvironment implements EventHandler {
	static final String CONFIG_PID = "org.greenscape.security";
	private Realm realm;
	private DefaultWebSecurityManager securityManager;
	private ResourceRegistry resourceRegistry;

	private BundleContext context;

	@Override
	public void handleEvent(Event event) {
		String name = (String) event.getProperty(ResourceEvent.RESOURCE_NAME);
		switch (event.getTopic()) {
		case ResourceRegistry.TOPIC_RESOURCE_REGISTERED:
			configureResource(name);
			break;
		case ResourceRegistry.TOPIC_RESOURCE_MODIFIED:
			break;
		case ResourceRegistry.TOPIC_RESOURCE_UNREGISTERED:
			break;
		}
	}

	@Activate
	public void activate(ComponentContext ctx, Map<String, Object> config) {
		context = ctx.getBundleContext();
		if (realm != null) {
			configureSecurityEnvironment(realm);
		}
	}

	@Reference(policy = ReferencePolicy.DYNAMIC, policyOption = ReferencePolicyOption.GREEDY)
	public void setRealm(Realm realm) {
		this.realm = realm;
		if (context == null) {
			return;
		}
		configureSecurityEnvironment(realm);
	}

	public void unsetRealm(Realm realm) {
		this.realm = null;
	}

	@Reference(policy = ReferencePolicy.DYNAMIC)
	public void setResourceRegistry(ResourceRegistry resourceRegistry) {
		this.resourceRegistry = resourceRegistry;
	}

	public void unsetResourceRegistry(ResourceRegistry resourceRegistry) {
		this.resourceRegistry = null;
	}

	private void configureSecurityEnvironment(Realm realm) {
		securityManager = new DefaultWebSecurityManager(realm);
		WebSessionManager sessionManager = new DefaultWebSessionManager();
		// securityManager.setSessionManager(sessionManager);
		SecurityUtils.setSecurityManager(securityManager);

		// IniWebEnvironment webenv = new IniWebEnvironment();
		DefaultWebEnvironment webenv = new DefaultWebEnvironment();
		Ini ini = new Ini();
		try {
			Section mainSection = ini.addSection("main");
			mainSection.put("rest.enabled", "false");
			Section urlsSection = ini.addSection("urls");
			urlsSection.put("/api/model/site/**", "anon[read]");
			urlsSection.put("/api/model/page/**", "anon[read]");
			urlsSection.put("/api/weblet", "rest[user]");
			urlsSection.put("/api/**", "rest[user]");
			urlsSection.put("/cp/**", "authc");
			// webenv.setIni(ini);
			// webenv.init();
			webenv.setWebSecurityManager(securityManager);

			// add filters and chains
			FilterChainManager fcManager = new DynamicFilterChainManager();
			FormAuthenticationFilter authc = new FormAuthenticationFilter();
			authc.setLoginUrl("/");
			fcManager.addFilter("authc", authc);
			HttpMethodPermissionFilter rest = new HttpMethodPermissionFilter();
			rest.setLoginUrl("/");
			rest.setUnauthorizedUrl(null);
			fcManager.addFilter("rest", rest);
			GuestLoginFilter guest = new GuestLoginFilter();
			fcManager.addFilter("guest", guest);
			NoSessionCreationFilter noSession = new NoSessionCreationFilter();
			fcManager.addFilter("noSession", noSession);

			fcManager.createChain("/api/**", "noSession,guest,rest");

			PathMatchingFilterChainResolver resolver = new PathMatchingFilterChainResolver();
			resolver.setFilterChainManager(fcManager);

			webenv.setFilterChainResolver(resolver);

			context.registerService(WebEnvironment.class, webenv, null);
		} catch (ConfigurationException e) {
			e.printStackTrace();
		}
	}

	private void configureResource(String resourceName) {
		Resource resource = resourceRegistry.getResource(resourceName);
		if (resource.getType() == ResourceType.Model) {
			configureModel((ModelResource) resource);
		} else if (resource.getType() == ResourceType.Weblet) {
			configureWeblet((WebletResource) resource);
		}
	}

	private void configureModel(ModelResource resource) {

	}

	private void configureWeblet(WebletResource resource) {
		// TODO Auto-generated method stub

	}
}
