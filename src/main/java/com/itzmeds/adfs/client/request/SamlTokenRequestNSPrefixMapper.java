package com.itzmeds.adfs.client.request;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

public class SamlTokenRequestNSPrefixMapper extends NamespacePrefixMapper {

	private static final String SOAP_PREFIX = "soap";
	private static final String SOAP_PREFIX_NS = "http://www.w3.org/2003/05/soap-envelope";
	private static final String ADDRESS_PREFIX = "a";
	private static final String ADDRESS_PREFIX_NS = "http://www.w3.org/2005/08/addressing";
	private static final String TRUST_PREFIX = "trust";
	private static final String TRUST_PREFIX_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
	private static final String WS_SEC_PREFIX = "wsse";
	private static final String WS_SEC_PREFIX_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	private static final String WS_SEC_UTIL_PREFIX = "wsu";
	private static final String WS_SEC_UTIL_PREFIX_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
	private static final String POLICY_PREFIX = "wsp";
	private static final String POLICY_PREFIX_NS = "http://schemas.xmlsoap.org/ws/2004/09/policy";
	private static final String DIGISIG_PREFIX = "ds";
	private static final String DIGISIG_PREFIX_NS = "http://www.w3.org/2000/09/xmldsig#";
	private static final String BINARY_TOKEN_PREFIX = "b";
	private static final String BINARY_TOKEN_PREFIX_NS = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";

	@Override
	public String getPreferredPrefix(String namespaceUri, String suggestion, boolean requirePrefix) {
		if (SOAP_PREFIX_NS.equals(namespaceUri))
			return SOAP_PREFIX;
		else if (ADDRESS_PREFIX_NS.equals(namespaceUri))
			return ADDRESS_PREFIX;
		else if (TRUST_PREFIX_NS.equals(namespaceUri))
			return TRUST_PREFIX;
		else if (WS_SEC_PREFIX_NS.equals(namespaceUri))
			return WS_SEC_PREFIX;
		else if (WS_SEC_UTIL_PREFIX_NS.equals(namespaceUri))
			return WS_SEC_UTIL_PREFIX;
		else if (POLICY_PREFIX_NS.equals(namespaceUri))
			return POLICY_PREFIX;
		else if (DIGISIG_PREFIX_NS.equals(namespaceUri))
			return DIGISIG_PREFIX;
		else if (BINARY_TOKEN_PREFIX_NS.equals(namespaceUri))
			return BINARY_TOKEN_PREFIX;
		return "";
	}

}
