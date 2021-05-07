package com.example.gateway.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.boot.actuate.security.AuthenticationAuditListener;
import org.springframework.boot.actuate.security.AuthorizationAuditListener;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.stereotype.Component;
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties
public class GlobalAuthenticationManagerConfig {

    // Publish authentication events
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(
            ApplicationEventPublisher applicationEventPublisher) {
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }

    // To enable audit events firing - alternative 1
    @Bean
    public AuthenticationAuditListener authenticationAuditListener() throws Exception {
        return new AuthenticationAuditListener();
    }

    // To enable audit events firing - alternative 1
    @Bean
    public AuthorizationAuditListener authorizationAuditListener() throws Exception {
        return new AuthorizationAuditListener();
    }

    // Listen to audit events and print them
    @EventListener
    public void auditEventHappened(AuditApplicationEvent auditApplicationEvent) {
        // System.out.println(auditApplicationEvent);
    }

    // The passwordEncoder with bcrypt as defeault
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // This delegates to registered UserDetailServices.
    public static class CompositeUserDetailsService implements UserDetailsService {

        private List<UserDetailsService> userDetailsServices = new LinkedList<>();

        public CompositeUserDetailsService() {
        }

        public void addService(UserDetailsService userDetailsService) {
            userDetailsServices.add(userDetailsService);
        }

        public List<UserDetailsService> getUserDetailsServices() {
            return userDetailsServices;
        }

        @Override
        public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
            if (userDetailsServices != null) {
                for (UserDetailsService srv : userDetailsServices) {
                    try {
                        final UserDetails details = srv.loadUserByUsername(login);
                        if (details != null) {
                            return details;
                        }
                    } catch (UsernameNotFoundException ex) {
                        assert ex != null;
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        throw ex;
                    }
                }
            }

            throw new UsernameNotFoundException("Unknown user");
        }

    }

    @Bean
    public CompositeUserDetailsService userDetailsService() {
        return new CompositeUserDetailsService();
    }

    public static class InMemoryGroupsProvider implements GroupsProvider {
        private List<String> groups = new ArrayList<>();

        public void setGroups(List<String> groups) {
            this.groups = groups;
        }

        @Override
        public List<String> getGroups() {
            return Collections.unmodifiableList(groups);
        }
    }

    @ConfigurationProperties(prefix = "inmemory")
    @Profile("inmemory")
    @Bean
    public InMemoryGroupsProvider inMemoryGroupsProvider() {
        return new InMemoryGroupsProvider();
    }

    @Component
    @EnableGlobalAuthentication
    @Profile("inmemory")
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public static class GlobalAuthenticationConfigurer extends GlobalAuthenticationConfigurerAdapter {
        @Autowired
        private CompositeUserDetailsService multiUserDetailsServiceWrapper;

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth, PasswordEncoder passwordEncoder)
                throws Exception {
            auth.inMemoryAuthentication().withUser("user").password(passwordEncoder.encode("user")).roles("USER").and()
                    .withUser("admin").password(passwordEncoder.encode("admin")).roles("ADMINISTRATOR");

            multiUserDetailsServiceWrapper.addService(auth.getDefaultUserDetailsService());
        }
    }

    public static class LdapGroupsProvider implements GroupsProvider {
        private List<String> groups = new ArrayList<>();

        @Override
        public List<String> getGroups() {
            groups.clear();
            final DefaultSpringSecurityContextSource contextSource =
                    new DefaultSpringSecurityContextSource("ldap://localhost:8389/dc=springframework,dc=org");
            contextSource.setAnonymousReadOnly(true);
            contextSource.afterPropertiesSet();

            LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
            try {
                ldapTemplate.afterPropertiesSet();

                SearchControls controls = new SearchControls();
                AndFilter filter = new AndFilter();
                filter.and(new EqualsFilter("objectclass", "groupOfUniqueNames"));

                // List<Group> groups =
                List<String> groups = ldapTemplate.search("ou=groups", filter.encode(), controls, new AttributesMapper<String>(){

                    @Override
                    public String mapFromAttributes(Attributes attributes) throws NamingException {
                        Attribute attribute = attributes.get("ou");
                        return (String) attribute.get() + "@ldap";
                    }
                });
                this.groups.addAll(groups);
            } catch (Exception e) {

            }
            return Collections.unmodifiableList(groups);
        }
    }

    @Profile("ldap")
    @Bean
    public LdapGroupsProvider ldapGroupsProvider() {
        return new LdapGroupsProvider();
    }
    @Configuration
    @EnableGlobalAuthentication
    @Profile("ldap")
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public static class LdapAM extends GlobalAuthenticationConfigurerAdapter {
        @Autowired
        private CompositeUserDetailsService multiUserDetailsServiceWrapper;

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth, PasswordEncoder passwordEncoder)
                throws Exception {
            auth.ldapAuthentication().userDnPatterns("uid={0},ou=people").groupSearchBase("ou=groups").contextSource()
                    .url("ldap://localhost:8389/dc=springframework,dc=org").and().passwordCompare()
                    .passwordEncoder(passwordEncoder).passwordAttribute("userPassword");
        }

        @Bean
        public UserDetailsService ldapUserDetailsService() {
            final DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(
                    "ldap://localhost:8389/dc=springframework,dc=org");
            contextSource.afterPropertiesSet();

            final DefaultLdapAuthoritiesPopulator defaultLdapAuthoritiesPopulator =
                new DefaultLdapAuthoritiesPopulator(contextSource, "ou=groups");
            defaultLdapAuthoritiesPopulator.setGroupSearchFilter("(uniqueMember={0})");
            final FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch("", "uid={0}", contextSource);
            final LdapUserDetailsService service = new LdapUserDetailsService(userSearch, defaultLdapAuthoritiesPopulator);
            service.setUserDetailsMapper(ldapUserDetailsMapper());
            multiUserDetailsServiceWrapper.addService(service);
            return service;
        }

        @Bean
        public LdapUserDetailsMapper ldapUserDetailsMapper() {
            return new LdapUserDetailsMapper();
        }
    }
}
