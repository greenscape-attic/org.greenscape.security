package org.greenscape.security;

import java.util.Map;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.Ini.Section;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.env.IniWebEnvironment;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

@Component(configurationPolicy = ConfigurationPolicy.REQUIRE, configurationPid = SecurityEnvironment.CONFIG_PID)
public class SecurityEnvironment {
	static final String CONFIG_PID = "org.greenscape.security";
	private Realm realm;
	private DefaultWebSecurityManager securityManager;
	private BundleContext context;

	@Activate
	public void activate(ComponentContext ctx, Map<String, Object> config) {
		context = ctx.getBundleContext();
		if (realm != null) {
			setRealm(realm);
		}
	}

	@Reference(policy = ReferencePolicy.DYNAMIC, policyOption = ReferencePolicyOption.GREEDY)
	public void setRealm(Realm realm) {
		this.realm = realm;
		if (context == null) {
			return;
		}
		securityManager = new DefaultWebSecurityManager(realm);
		WebSessionManager sessionManager = new DefaultWebSessionManager();
		securityManager.setSessionManager(sessionManager);
		SecurityUtils.setSecurityManager(securityManager);

		IniWebEnvironment webenv = new IniWebEnvironment();
		Ini ini = new Ini();
		try {
			Section mainSection = ini.addSection("main");
			Section urlsSection = ini.addSection("urls");
			urlsSection.put("/api/model/site/**", "anon[read]");
			urlsSection.put("/api/model/page/**", "anon[read]");
			// urlsSection.put("/api/weblet", "rest[user]");
			// urlsSection.put("/api/**", "rest[user]");
			urlsSection.put("/cp/**", "authc");
			webenv.setIni(ini);
			webenv.init();
			webenv.setWebSecurityManager(securityManager);
			webenv.getObject("authc", FormAuthenticationFilter.class).setLoginUrl("/");
			webenv.getObject("rest", HttpMethodPermissionFilter.class).setLoginUrl("/");
			webenv.getObject("rest", HttpMethodPermissionFilter.class).setUnauthorizedUrl(null);

			context.registerService(WebEnvironment.class, webenv, null);
		} catch (ConfigurationException e) {
			e.printStackTrace();
		}
	}

	public void unsetRealm(Realm realm) {
		this.realm = null;
	}
}
