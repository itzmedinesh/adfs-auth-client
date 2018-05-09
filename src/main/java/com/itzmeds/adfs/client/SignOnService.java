package com.itzmeds.adfs.client;

import com.itzmeds.adfs.client.response.jwt.BinarySecurityToken;
import com.itzmeds.adfs.client.response.saml.RequestedSecurityToken.Assertion;

/**
 * Contract provides methods to generate sign-on request for ADFS
 * authentication, parse the successful response to provide SAML, BST, JWT
 * tokens.
 * 
 * @author itzmeds
 *
 */
public interface SignOnService {

	enum TokenTypes {
		SAML_TOKEN_TYPE("urn:oasis:names:tc:SAML:2.0:assertion"), BST_TOKEN_TYPE(
				"urn:ietf:params:oauth:token-type:jwt"), JWT_TOKEN_TYPE("urn:ietf:params:oauth:token-type:jwt");

		private final String name;

		private TokenTypes(String type) {
			name = type;
		}

		public String toString() {
			return this.name;
		}

	}

	String ACTION_URL = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";
	String PASSWORD_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";

	String KEY_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
	String REQUEST_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";

	/**
	 * Generates sign-on request for ADFS authentication
	 * 
	 * @param username
	 *            - logon uid
	 * @param password
	 *            - logon pwd
	 * @param tokenType
	 *            - type of token to generate on successful authentication with ADFS
	 * @param targetUrl
	 *            - ADFS service endpoint url
	 * @param clientAddress
	 *            - client address registered with ADFS for access
	 * @return String - XML request to sign-on to ADFS
	 * @throws SignOnException
	 *             - thrown when the sign-on request XML does not validate against
	 *             the schema definition
	 */
	public String createSignOnRequest(String username, String password, TokenTypes tokenType, String targetUrl,
			String clientAddress) throws SignOnException;

	/**
	 * Parses the successfully authenticated XML response from ADFS to extract SAML
	 * assertion token
	 * 
	 * @param response
	 *            - successfully authenticated XML response from ADFS
	 * @return Assertion - SAML assertion
	 * @throws SignOnException
	 *             - thrown when the SAML assertion XML does not validate against
	 *             the schema definition
	 */
	public Assertion getSamlToken(String response) throws SignOnException;

	/**
	 * Parses the successfully authenticated XML response from ADFS to extract
	 * binary security token
	 * 
	 * @param response
	 *            - successfully authenticated XML response from ADFS
	 * @return BinarySecurityToken - Base64 encoded binary token
	 * @throws SignOnException
	 *             - thrown when the binary security token XML does not validate
	 *             against the schema definition
	 */
	public BinarySecurityToken getBinarySecurityToken(String response) throws SignOnException;

	/**
	 * Parses the successfully authenticated XML response from ADFS to extract json
	 * web token
	 * 
	 * @param response
	 *            - successfully authenticated XML response from ADFS
	 * @return String - JSON web token
	 * @throws SignOnException
	 *             - thrown when the json web token XML does not validate against
	 *             the schema definition
	 */
	public String getJsonWebToken(String response) throws SignOnException;

}
