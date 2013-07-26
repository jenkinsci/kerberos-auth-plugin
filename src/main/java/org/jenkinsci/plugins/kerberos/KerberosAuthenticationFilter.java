package org.jenkinsci.plugins.kerberos;

import hudson.Functions;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;

import java.io.IOException;
import java.lang.reflect.Array;
import java.security.acl.Group;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sourceforge.spnego.SpnegoAuthenticator;
import net.sourceforge.spnego.SpnegoHttpFilter.Constants;
import net.sourceforge.spnego.SpnegoHttpServletResponse;
import net.sourceforge.spnego.SpnegoPrincipal;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.apache.oro.text.regex.PatternMatcher;

public class KerberosAuthenticationFilter implements Filter {

    private SpnegoAuthenticator authenticator;

    private boolean retry = false;
    private String user;
    private String password;
    private String krbConf;
    private String pattern;


    private void initAuthenticator() {
        Map<String, String> props = new HashMap<String, String>();


        if (krbConf == null || krbConf.isEmpty()) {
            props.put("spnego.krb5.conf", Hudson.getInstance().getRootDir()
                    .getPath()
                    + "/krb5.conf");
        } else {
            props.put("spnego.krb5.conf", krbConf);
        }

        props.put("spnego.login.conf", Hudson.getInstance().getRootDir()
                .getPath()
                + "/jaas.conf");
        /*

        user: http_srv012182
        pass: vA8TJ0KhK8UuE

        */

        props.put(Constants.ALLOW_BASIC, "true");
        props.put("spnego.allow.localhost", "true");
        props.put("spnego.allow.unsecure.basic", "true");
        props.put("spnego.login.client.module", "spnego-client");


        props.put("spnego.preauth.username", user);
        props.put("spnego.preauth.password", password);
        props.put("spnego.login.server.module", "spnego-server");
        props.put("spnego.prompt.ntlm", "true");
        props.put("spnego.allow.delegation", "true");
        props.put("spnego.logger.level", "1");


        try {
            this.authenticator = new SpnegoAuthenticator(props);
        } catch (Exception e) {
            // SILENCE!
        }
    }

    public KerberosAuthenticationFilter() {

    }

    public KerberosAuthenticationFilter(String user, String password, String krbConf, String pattern) {
        this.user = user;
        this.password = password;
        this.krbConf = krbConf;
        this.pattern = pattern;
    }

    public void destroy() {


    }

    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {


        retry = false;

        if (SecurityContextHolder.getContext().getAuthentication() != null
                && SecurityContextHolder.getContext().getAuthentication()
                .isAuthenticated() && !Functions.isAnonymous()) {

            chain.doFilter(request, response);
            return;

        }

        final HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (pattern != null && !pattern.isEmpty()) {

            Pattern p = Pattern.compile(pattern);
            Matcher matcher = p.matcher(httpRequest.getRequestURL().toString());
            if (matcher.find()) {
                chain.doFilter(httpRequest, response);
                return;

            }
        }


        final SpnegoHttpServletResponse spnegoResponse = new SpnegoHttpServletResponse(
                (HttpServletResponse) response);

        // client/caller principal
        SpnegoPrincipal principal = null;

        try {
            if (authenticator == null) {
                initAuthenticator();
            }
            principal = this.authenticator.authenticate(httpRequest,
                    spnegoResponse);
        } catch (Exception e) {

            // SILENCE!
        }

        // context/auth loop not yet complete
        if (spnegoResponse.isStatusSet()) {
            return;
        }
        //try to make a new instance of the authenticator before fail!
        // assert
        if (null == principal) {
            System.out.println("No Credentials");
            if (!retry) {
                System.out.println("Try again with new authenticator.");
                retry = true;
                initAuthenticator();
                chain.doFilter(httpRequest, response);
                return;
            }

            System.out.println("Retry failed.");
            spnegoResponse.setStatus(
                    HttpServletResponse.SC_FORBIDDEN, true);
            chain.doFilter(httpRequest, response);
            return;
        }


        List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();


        String username = principal.getName().split("@")[0];

        List<String> groups = new LinkedList<String>();

        //add all groups
        for (String group : groups) {

            grantedAuthorities.add(new ADGroupAuthority(group));
        }


        grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                username,
                username,
                grantedAuthorities.toArray(new GrantedAuthority[]{}));

        SecurityContextHolder.getContext().setAuthentication(token);

        retry = false;
        chain.doFilter(httpRequest, response);
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public boolean isRetry() {
        return retry;
    }

    public void setRetry(boolean retry) {
        this.retry = retry;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public SpnegoAuthenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(SpnegoAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    public String getKrbConf() {
        return krbConf;
    }

    public void setKrbConf(String krbConf) {
        this.krbConf = krbConf;
    }

    public void init(FilterConfig arg0) throws ServletException {

    }

}
