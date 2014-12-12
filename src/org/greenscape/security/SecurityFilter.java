package org.greenscape.security;

import javax.servlet.Filter;

import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

@Component(property = { "pattern=/.*", "service.ranking=1" }, service = { Filter.class })
public class SecurityFilter extends AbstractShiroFilter {
	private WebEnvironment environment;

	@Override
	public void init() throws Exception {
		if (environment == null) {
			throw new Exception("Web Environment not setup!");
		}
		setSecurityManager(environment.getWebSecurityManager());

		FilterChainResolver resolver = environment.getFilterChainResolver();
		if (resolver != null) {
			setFilterChainResolver(resolver);
		}
	}

	@Reference(policy = ReferencePolicy.DYNAMIC, policyOption = ReferencePolicyOption.GREEDY)
	public void setWebEnvironment(WebEnvironment webEnvironment) {
		this.environment = webEnvironment;
	}

	public void unsetWebEnvironment(WebEnvironment webEnvironment) {
		this.environment = webEnvironment;
	}
}
