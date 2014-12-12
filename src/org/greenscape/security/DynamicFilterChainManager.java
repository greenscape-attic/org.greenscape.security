package org.greenscape.security;

import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.osgi.service.component.annotations.Component;

@Component(service = FilterChainManager.class)
public class DynamicFilterChainManager extends DefaultFilterChainManager {
	public DynamicFilterChainManager() {
		// TODO Auto-generated constructor stub
	}
}
