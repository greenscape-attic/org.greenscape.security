package org.greenscape.security;

import java.util.List;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.greenscape.core.model.UserEntity;
import org.greenscape.core.model.UserModel;
import org.greenscape.core.service.Service;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

@Component(service = { Realm.class })
public class GreenscapeRealm extends AuthorizingRealm {
	private Service service;

	public GreenscapeRealm() {
		setCachingEnabled(true);
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		String username = null;
		char[] password = null;
		if (token instanceof UsernamePasswordToken) {
			UsernamePasswordToken passwordToken = (UsernamePasswordToken) token;
			username = passwordToken.getUsername();
			password = passwordToken.getPassword();
			List<UserEntity> user = service.find(UserModel.MODEL_NAME, UserEntity.USER_NAME, username);
			if (user.isEmpty()) {
				return null;
			}
		}
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(username, password, getName());
		return info;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String user = getAvailablePrincipal(principals).toString();
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(); // roleNames
		// info.setStringPermissions(permissions);
		return info;
	}

	@Reference(policy = ReferencePolicy.DYNAMIC, policyOption = ReferencePolicyOption.GREEDY)
	public void setService(Service service) {
		this.service = service;
	}

	public void unsetService(Service service) {
		this.service = null;
	}
}
