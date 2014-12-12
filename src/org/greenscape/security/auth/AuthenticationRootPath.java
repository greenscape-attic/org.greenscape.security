package org.greenscape.security.auth;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.greenscape.core.service.Service;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

@Path("auth")
@Component(service = Object.class)
public class AuthenticationRootPath {
	private Service service;

	@Path("/signin")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public String signin(LoginParam param) {
		Subject subject = SecurityUtils.getSubject();
		if (!subject.isAuthenticated()) {
			UsernamePasswordToken token = new UsernamePasswordToken(param.getUsername(), param.getPassword());
			token.setRememberMe(param.isRememberMe());
			try {
				subject.login(token);
			} catch (AuthenticationException e) {
				throw new WebApplicationException(Response.status(Status.UNAUTHORIZED)
						.entity("Username or password is incorrect").build());
			}
		}
		return subject.getPrincipal().toString();
	}

	@Path("/signout")
	@POST
	@Produces(MediaType.APPLICATION_JSON)
	public String signout() {
		Subject subject = SecurityUtils.getSubject();
		subject.logout();
		return Response.status(Status.OK).build().toString();
	}

	@Path("/register")
	@POST
	public void register() {

	}

	@Reference(policy = ReferencePolicy.DYNAMIC, policyOption = ReferencePolicyOption.GREEDY)
	public void setService(Service service) {
		this.service = service;
	}

	public void unsetService(Service service) {
		this.service = null;
	}
}
