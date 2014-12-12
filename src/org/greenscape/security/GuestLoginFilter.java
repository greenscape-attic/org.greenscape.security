package org.greenscape.security;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.PathMatchingFilter;

public class GuestLoginFilter extends PathMatchingFilter {
	@Override
	protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) {
		if (!SecurityUtils.getSubject().isAuthenticated()) {
			UsernamePasswordToken token = new UsernamePasswordToken("guest", "guest");
			SecurityUtils.getSubject().login(token);
		}
		return true;
	}
}
