package org.greenscape.security;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.greenscape.core.Action;
import org.greenscape.core.Resource;
import org.greenscape.core.ResourceRegistry;
import org.greenscape.core.model.Permission;
import org.greenscape.core.model.PermissionModel;
import org.greenscape.core.model.RoleModel;
import org.greenscape.core.model.UserEntity;
import org.greenscape.core.model.UserModel;
import org.greenscape.core.service.Service;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

@Component(service = { Realm.class })
public class GreenscapeRealm extends AuthorizingRealm {
	private final static String NAME = "GreenscapeRealm";
	private Service service;
	private ResourceRegistry resourceRegistry;

	public GreenscapeRealm() {
		setName(NAME);
		setCachingEnabled(true);
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		SimpleAuthenticationInfo info = null;
		if (token instanceof UsernamePasswordToken) {
			String username = null;
			char[] password = null;
			UsernamePasswordToken passwordToken = (UsernamePasswordToken) token;
			username = passwordToken.getUsername();
			password = passwordToken.getPassword();
			List<UserEntity> user = service.find(UserModel.MODEL_NAME, UserEntity.USER_NAME, username);
			if (user.isEmpty()) {
				return null;
			}
			info = new SimpleAuthenticationInfo(user.get(0).getId(), password, getName());
		}

		return info;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		Object id = getAvailablePrincipal(principals);
		UserEntity user = service.find(UserModel.MODEL_NAME, id);
		Map<String, List<String>> properties = new HashMap<>();
		properties.put(RoleModel.MODEL_ID, new ArrayList<String>(user.getRoles()));
		List<RoleModel> roles = service.find(RoleModel.MODEL_NAME, properties);
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		for (RoleModel role : roles) {
			info.addRole(role.getName());
			List<Permission> permissions = service.find(PermissionModel.MODEL_NAME, PermissionModel.ROLE_ID,
					role.getModelId());
			for (Permission permission : permissions) {
				Resource resource = resourceRegistry.getResource(permission.getName());
				StringBuilder perm = new StringBuilder();
				perm.append(permission.getName()).append(":").append(permission.getScope().toString()).append(":");
				long actionIds = permission.getActionIds();
				List<Action> actions = resource.getPermission().getSupports();
				for (Action action : actions) {
					if ((actionIds & action.getBit()) == action.getBit()) {
						perm.append(action.getName()).append(",");
					}
				}
				perm.deleteCharAt(perm.length() - 1);
				info.addObjectPermission(new WildcardPermission(perm.toString()));
			}
		}
		return info;
	}

	@Reference(policy = ReferencePolicy.DYNAMIC, policyOption = ReferencePolicyOption.GREEDY)
	public void setService(Service service) {
		this.service = service;
	}

	public void unsetService(Service service) {
		this.service = null;
	}

	@Reference(policy = ReferencePolicy.DYNAMIC)
	public void setResourceRegistry(ResourceRegistry resourceRegistry) {
		this.resourceRegistry = resourceRegistry;
	}

	public void unsetResourceRegistry(ResourceRegistry resourceRegistry) {
		this.resourceRegistry = null;
	}
}
