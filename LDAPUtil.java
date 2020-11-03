/**
 * 
 */
package com.dxc.art.util;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.springframework.stereotype.Component;

import com.dxc.art.domain.LoggedinUser;

/**
 * @author asarkar28
 *
 */

@Component
public class LDAPUtil {
	
	private static String prefixUserIDcheck = "uid=";
	private static String basePrefix = "ou=employees,o=bpo";
	private static String factory = "com.sun.jndi.ldap.LdapCtxFactory";
	private static String url = "ldap://10.159.37.98:389";
	private static String artGroup = "ou=ART,ou=groups,o=bpo";
	private boolean isSupervisor = false;
	private boolean isAdmin = false;


	public LoggedinUser ldapAuthentication(String name, String password, LoggedinUser loggedinUser) {
		
		DirContext ctx = null;
		ctx = createContext(name, password);
		boolean flag = false;

		if (ctx == null) {
			System.out.println("Invalid credentials.");
		} else {
			System.out.println("Credential validated.");
			flag = true;
		}

		String groupValART = getGroups(name, "", "cn", "*", ctx, artGroup);
		
		if (groupValART.isEmpty()) {
			System.out.println("User not present in ART group");
			flag = false;
		} else {
			System.out.println("Group is " + groupValART);
			if(groupValART.equals("Admin")) {
				isAdmin = true ;
				flag = true ;
			}
			if(groupValART.equals("Supervisor")) {
				isSupervisor = true ;
				flag = true ;
			}
		}
		
		loggedinUser.setAuthenticated(flag);
		loggedinUser.setAdmin(isAdmin);
		loggedinUser.setSupervisor(isSupervisor);

		return loggedinUser;
		
	}

	private DirContext createContext(String uid, String pwd) {
		DirContext ctx = null;
		
		System.out.println("uid: " + uid);
		System.out.println("pwd: " + pwd);
		System.out.println("url: " + url);
		System.out.println("prefixUserIDcheck: " + prefixUserIDcheck);
		System.out.println("basePrefix: " + basePrefix);
		System.out.println("SECURITY_PRINCIPAL: " + prefixUserIDcheck + uid + "," + basePrefix);
		System.out.println("factory: " + factory);
		try {
			Hashtable table = new Hashtable();
			table.put(Context.PROVIDER_URL, url);
			if (uid != null) {
				table.put(Context.SECURITY_PRINCIPAL, prefixUserIDcheck+ uid + "," + basePrefix);

				table.put(Context.SECURITY_CREDENTIALS, pwd);
				table.put(Context.INITIAL_CONTEXT_FACTORY,factory);
			}
			ctx = new InitialDirContext(table);
		} catch (CommunicationException cex) {
			System.out.println("cex.getMessage()==" + cex.getMessage());
		} catch (NamingException nex) {
			System.out.println("nex.getMessage()==" + nex.getMessage());
		}

		return ctx;
	}
	
	public String getGroups(String uid, String pwd, String cn, String objectClass, DirContext ctx, String roleGroup) {
		String grpName = "";

		try {
			if (cn == null) {
				return "";
			}

			String userDN = uid;
			String userDNl = userDN.toLowerCase();
			String userDNu = userDN.toUpperCase();

			if (!userDN.startsWith(prefixUserIDcheck)) {
				userDN = prefixUserIDcheck + userDN + "," + basePrefix;
				userDNl = prefixUserIDcheck + userDNl + "," + basePrefix;
				userDNu = prefixUserIDcheck + userDNu + "," + basePrefix;
			}

			Map filter = new HashMap();
//			filter.put("cn", "Admin");

			filter.put("objectclass", "groupOfUniqueNames");
			String filterStr = getFilter(filter);
			SearchControls constraints = new SearchControls();

			constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
			NamingEnumeration results = ctx.search(roleGroup, filterStr, constraints);

			if (results != null) {
				while (results.hasMoreElements()) {
					SearchResult si = (SearchResult) results.next();
					Attributes atts = si.getAttributes();
					Attribute att = atts.get("uniqueMember");

					if (att != null) {
						if (att.contains(userDN) || att.contains(userDNl) || att.contains(userDNu)) {
							Attribute grpatt = atts.get("cn");
							String fgroup = (String) grpatt.get();
							grpName = fgroup + "," + grpName;
							// return grpName;

						}
					}
				}
			}
		} catch (Exception ex) {
			System.out.println(" Error in Authentication 1 ");
		} finally {
			// ctx = releaseContext(ctx);
		}
		if (grpName == "")
			return "";
		grpName = grpName.substring(0, grpName.length() - 1);
		return grpName;
	}
	
	private static String getFilter(Map filterMap) {
		if (filterMap != null) {
			StringBuffer buf = new StringBuffer("(&(");
			Set ks = filterMap.keySet();
			Iterator itr = ks.iterator();
			boolean first = true;
			while (itr.hasNext()) {
				String key = (String) itr.next();
				String value = (String) filterMap.get(key);
				if (value != null) {
					if (!first) {
						buf.append("(");
					}
					buf.append(key);
					buf.append("=");
					buf.append(value);
					buf.append(')');
					first = false;
				}
			}
			buf.append(")");

			return buf.toString();
		}
		return null;
	}

}
