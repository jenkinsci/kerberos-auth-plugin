package org.jenkinsci.plugins.kerberos;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.util.PluginServletFilter;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.ietf.jgss.GSSException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

import javax.security.auth.login.LoginException;
import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.PrivilegedActionException;

public class SSOKerberosSecurityRealm extends SecurityRealm {

    private KerberosAuthenticationFilter filter;

    @DataBoundConstructor
    public SSOKerberosSecurityRealm(String kdc, String realm, String krbConf, String user, String password, Boolean overwrite, String pattern,Boolean logout) {
        this.realm = realm;
        this.kdc = kdc;
        this.overwrite = overwrite;
        this.krbConf = krbConf;
        this.user = user;
        this.password = password;
        this.pattern = pattern;

        this.logout = logout==null?false:logout;

        try {
            setUpKerberos();
        } catch (Exception e) {
            // SILENCE!
            return;
        }
        try {

            filter = new KerberosAuthenticationFilter(user, password, krbConf, pattern);

            try {
                PluginServletFilter.removeFilter(filter);
            } catch (ServletException e) {

            }
            PluginServletFilter.addFilter(filter);

        } catch (Exception e) {
            // SILENCE!
        }
    }

    private String kdc;
    private String realm;

    private String user;
    private String password;

    private String krbConf;
    private Boolean overwrite;

    private String pattern;

    private Boolean logout;


    @Override
    public Filter createFilter(FilterConfig filterConfig) {


        try {
            PluginServletFilter.removeFilter(filter);
            PluginServletFilter.addFilter(filter);

        } catch (ServletException e) {
            // SILENCE!
        }


        return super.createFilter(filterConfig);
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication)
                    throws AuthenticationException {


                return authentication;
            }
        });
    }

    @Override
    public boolean canLogOut() {
        if(logout){
            return super.canLogOut();
        }else return false;
    }



    private void setUpKerberos() throws LoginException, FileNotFoundException,
            GSSException, PrivilegedActionException, URISyntaxException {

        try {
            createConfigFiles();
            System.setProperty("java.security.krb5.realm", realm);
            System.setProperty("java.security.krb5.kdc", kdc);
            System.setProperty("http.auth.preference", "SSPI");
            System.setProperty("sun.security.krb5.debug", "false");
            System.setProperty("javax.security.auth.useSubjectCredsOnly",
                    "false");

            System.setProperty("java.security.krb5.conf", krbConf);

            System.setProperty("java.security.auth.login.config", Hudson
                    .getInstance().getRootDir().getPath()
                    + "/jaas.conf");

        } catch (IOException e) {
            // SILENCE!
        }

    }

    private void createConfigFiles() throws IOException {
        // Jenkins will write new default kerberos config stuff, if they are not
        // found on JENKINS_HOME

        // The admin have to make sure that useTicketCache=true
        /*    A will not create a new krb5.conf anymore, load it from /etc/krb5.conf
        File krbConf = new File(Hudson.getInstance().getRootDir().getPath()
                + "/krb5.conf");
        if (overwrite && krbConf.exists()) {
            krbConf.delete();
        }

        if (!krbConf.exists()) {
            krbConf.createNewFile();

            FileWriter writer = new FileWriter(krbConf);
            writer.write("[libdefaults]\n");
            writer.write("default_tgs_enctypes = arcfour-hmac arcfour-hmac-md5 rc4-hmac des-cbc-crc des-cbc-md5\n");
            writer.write("default_tkt_enctypes = arcfour-hmac arcfour-hmac-md5 rc4-hmac des-cbc-crc des-cbc-md5\n");
            writer.write("permitted_enctypes = arcfour-hmac arcfour-hmac-md5 rc4-hmac des-cbc-crc des-cbc-md5\n");
            writer.write("udp_preference_limit = 1\n");
            writer.write("[appdefaults]\n");
            writer.write("forwardable = true");
            writer.flush();
            writer.close();
        }     */

        File jaasConf = new File(Hudson.getInstance().getRootDir().getPath()
                + "/jaas.conf");

        if (overwrite && jaasConf.exists()) {
            jaasConf.delete();
        }

        if (!jaasConf.exists()) {
            jaasConf.createNewFile();

            FileWriter writer = new FileWriter(jaasConf);
            writer.write("Kerberos {\n");
            writer.write("     com.sun.security.auth.module.Krb5LoginModule required\n");
            writer.write(" doNotPrompt=false useTicketCache=true useKeyTab=false;\n");
            writer.write("};");

            writer.write("spnego-client {");
            writer.write("	com.sun.security.auth.module.Krb5LoginModule required;\n");
            writer.write("}\n;");
            writer.write("spnego-server {\n");
            writer.write("  com.sun.security.auth.module.Krb5LoginModule required storeKey=true isInitiator=false useKeyTab=false tryFirstPass=true storePass=true;\n");
            writer.write("};\n");

            writer.write("com.sun.security.jgss.initiate {\n");
            writer.write(" com.sun.security.auth.module.Krb5LoginModule required\n");
            writer.write(" doNotPrompt=true\n");
            writer.write(" storeKey=true;\n");
            writer.write("};");
            writer.write("com.sun.security.jgss.accept {\n");
            writer.write(" com.sun.security.auth.module.Krb5LoginModule required\n");
            writer.write(" useKeyTab=false\n");
            writer.write(" storeKey=true;\n");

            writer.write("};\n");

            writer.flush();
            writer.close();
        }

    }

    public String getKdc() {
        return kdc;
    }

    public void setKdc(String kdc) {
        this.kdc = kdc;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public Boolean getOverwrite() {
        return overwrite;
    }

    public void setOverwrite(Boolean overwrite) {
        this.overwrite = overwrite;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getDisplayName() {
            return "Kerberos SSO";
        }

    }

    public String getKrbConf() {
        return krbConf;
    }

    public void setKrbConf(String krbConf) {
        this.krbConf = krbConf;
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

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public Boolean getLogout() {
        return logout;
    }

    public void setLogout(Boolean logout) {
        this.logout = logout;
    }
}
