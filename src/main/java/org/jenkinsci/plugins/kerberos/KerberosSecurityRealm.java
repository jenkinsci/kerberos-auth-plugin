package org.jenkinsci.plugins.kerberos;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

/**
 * @author Marcelo Brunken
 */
public class KerberosSecurityRealm extends AbstractPasswordBasedSecurityRealm {
    @DataBoundConstructor
    public KerberosSecurityRealm(String kdc, String realm, Boolean overwrite) {
        this.realm = realm;
        this.kdc = kdc;
        this.overwrite = overwrite;

        setUpKerberos();

    }

    private String kdc;
    private String realm;
    private Boolean overwrite;

    @Override
    protected UserDetails authenticate(String username, String password)
            throws AuthenticationException {
        // TODO: verify that the username&password pair is correct
        setUpKerberos();
        LoginContext lc = null;

        try {
            lc = new LoginContext("Kerberos", new UserPasswordCallBackHandler(
                    username, password));

            lc.login();

            List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();


            // customize for AD groups
            List<String> groups = new LinkedList<String>();

            //add all groups
            for (String group : groups) {

                grantedAuthorities.add(new ADGroupAuthority(group));
            }


            grantedAuthorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);


            return new User(username, "", true, true, true, true,
                    grantedAuthorities.toArray(new GrantedAuthority[]{}));

        } catch (LoginException le) {
            throw new UsernameNotFoundException(le.getMessage());

        }

    }

    private void setUpKerberos() {

        try {
            createConfigFiles();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        System.setProperty("java.security.krb5.realm", realm);
        System.setProperty("java.security.krb5.kdc", kdc);
        System.setProperty("http.auth.preference", "SSPI");
        System.setProperty("sun.security.krb5.debug", "false");
        System.setProperty("java.security.krb5.conf", Hudson.getInstance()
                .getRootDir().getPath()
                + "/krb5.conf");
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        System.setProperty("java.security.auth.login.config", Hudson
                .getInstance().getRootDir().getPath()
                + "/jaas.conf");

    }

    private void createConfigFiles() throws IOException {
        // Jenkins will write new default kerberos config stuff, if they are not
        // found on JENKINS_HOME

        File krbConf = new File(Hudson.getInstance().getRootDir().getPath()
                + "/krb5.conf");

        if (overwrite && krbConf.exists()) {
            krbConf.delete();
        }

        if (!krbConf.exists()) {
            krbConf.createNewFile();

            FileWriter writer = new FileWriter(krbConf);
            writer.write("[libdefaults]\n");
            writer.write("default_tkt_enctypes =  DES-CBC-CRC DES-CBC-MD5\n");
            writer.write("default_tgs_enctypes = DES-CBC-CRC DES-CBC-MD5\n");
            writer.write("permitted_enctypes = DES-CBC-CRC DES-CBC-MD5\n");
            writer.write("udp_preference_limit = 1\n");
            writer.write("[appdefaults]\n");
            writer.write("forwardable = true");
            writer.flush();
            writer.close();
        }

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
            writer.write(" doNotPrompt=false useTicketCache=false useKeyTab=false;\n");
            writer.write("};");

            writer.flush();
            writer.close();
        }

    }

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
        throw new UsernameNotFoundException(username);
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupname)
            throws UsernameNotFoundException, DataAccessException {
        throw new UsernameNotFoundException("No group in Kerberoes: "
                + groupname);
    }

    public String getKdc() {
        return kdc;
    }

    public String getRealm() {
        return realm;
    }

    public void setKdc(String kdc) {
        this.kdc = kdc;
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
            return "Kerberos";
        }

    }
}
