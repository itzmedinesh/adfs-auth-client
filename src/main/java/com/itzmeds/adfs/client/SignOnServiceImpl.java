package com.itzmeds.adfs.client;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Base64;
import java.util.StringTokenizer;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

import com.itzmeds.adfs.client.request.AppliesTo;
import com.itzmeds.adfs.client.request.Body;
import com.itzmeds.adfs.client.request.EndpointReference;
import com.itzmeds.adfs.client.request.Envelope;
import com.itzmeds.adfs.client.request.Header;
import com.itzmeds.adfs.client.request.ObjectFactory;
import com.itzmeds.adfs.client.request.Password;
import com.itzmeds.adfs.client.request.RequestSecurityToken;
import com.itzmeds.adfs.client.request.SamlTokenRequestNSPrefixMapper;
import com.itzmeds.adfs.client.request.Security;
import com.itzmeds.adfs.client.request.UsernameToken;
import com.itzmeds.adfs.client.response.jwt.BinarySecurityToken;
import com.itzmeds.adfs.client.response.jwt.RequestSecurityTokenResponse;
import com.itzmeds.adfs.client.response.saml.RequestedSecurityToken.Assertion;

public class SignOnServiceImpl implements SignOnService {

	@Override
	public String createSignOnRequest(String username, String password, TokenTypes tokenType, String targetUrl,
			String clientAddress) throws SignOnException {

		ObjectFactory objectFactory = new ObjectFactory();
		Envelope envelope = objectFactory.createEnvelope();
		Header header = objectFactory.createHeader();
		header.setAction(ACTION_URL);
		header.setTo(targetUrl);

		Security security = objectFactory.createSecurity();
		UsernameToken usernameToken = objectFactory.createUsernameToken();
		usernameToken.setId("UsernameToken-1");

		Password passwordObj = objectFactory.createPassword();
		passwordObj.setType(PASSWORD_TYPE);
		passwordObj.setContent(password);

		usernameToken.setPassword(passwordObj);
		usernameToken.setUsername(username);

		security.setUsernameToken(usernameToken);

		header.setSecurity(security);

		Body body = objectFactory.createBody();

		RequestSecurityToken reqSecToken = objectFactory.createRequestSecurityToken();
		reqSecToken.setKeyType(KEY_TYPE);
		reqSecToken.setRequestType(REQUEST_TYPE);
		reqSecToken.setTokenType(tokenType.toString());

		AppliesTo appliesTo = objectFactory.createAppliesTo();

		EndpointReference endpointRef = objectFactory.createEndpointReference();
		endpointRef.setAddress(clientAddress);

		appliesTo.setEndpointReference(endpointRef);

		reqSecToken.setAppliesTo(appliesTo);

		body.setRequestSecurityToken(reqSecToken);

		envelope.setHeader(header);
		envelope.setBody(body);

		StringWriter samlStringWriter = new StringWriter();

		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(Envelope.class);
			Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
			jaxbMarshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper", new SamlTokenRequestNSPrefixMapper());

			jaxbMarshaller.marshal(envelope, samlStringWriter);
		} catch (Throwable e) {
			throw new SignOnException(e);
		}

		return samlStringWriter.toString();

	}

	@Override
	public Assertion getSamlToken(String response) throws SignOnException {

		int assertionStartIndex = response.indexOf("<Assertion") + 10;
		int assertionEndIndex = response.indexOf("</Assertion>") + 12;

		String assertion = "<Assertion xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""
				+ response.substring(assertionStartIndex, assertionEndIndex);

		assertion = assertion.replace("xmlns=\"" + TokenTypes.SAML_TOKEN_TYPE.toString() + "\"", "");

		System.out.println(assertion);

		JAXBElement<Assertion> assertionresponse = null;

		XMLInputFactory xif = XMLInputFactory.newFactory();
		try {
			XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(assertion));

			JAXBContext jaxbContext = JAXBContext.newInstance(Assertion.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();

			assertionresponse = jaxbUnmarshaller.unmarshal(xsr, Assertion.class);

		} catch (Throwable e) {
			throw new SignOnException(e);
		}

		return assertionresponse != null ? assertionresponse.getValue() : null;
	}

	@Override
	public BinarySecurityToken getBinarySecurityToken(String response) throws SignOnException {

		int binaryTokenStartIndex = response.indexOf("<trust:RequestSecurityTokenResponse>") + 36;
		int binaryTokenEndIndex = response.indexOf("</trust:RequestSecurityTokenResponse>") + 37;

		String jsonWebTokenStr = "<trust:RequestSecurityTokenResponse xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
				+ response.substring(binaryTokenStartIndex, binaryTokenEndIndex);

		JAXBElement<RequestSecurityTokenResponse> securityTokenResponse = null;

		XMLInputFactory xif = XMLInputFactory.newFactory();
		try {
			XMLStreamReader xsr = xif.createXMLStreamReader(new StringReader(jsonWebTokenStr));

			JAXBContext jaxbContext = JAXBContext.newInstance(RequestSecurityTokenResponse.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();

			securityTokenResponse = jaxbUnmarshaller.unmarshal(xsr, RequestSecurityTokenResponse.class);

		} catch (Throwable e) {
			throw new SignOnException(e);
		}

		return securityTokenResponse != null && securityTokenResponse.getValue() != null
				&& securityTokenResponse.getValue().getRequestedSecurityToken() != null
						? securityTokenResponse.getValue().getRequestedSecurityToken().getBinarySecurityToken()
						: null;
	}

	@Override
	public String getJsonWebToken(String response) throws SignOnException {

		BinarySecurityToken bst = getBinarySecurityToken(response);

		String jsonWebToken = null;

		if (bst != null) {

			String binarySecToken = new String(bst.getValue());
			
			StringTokenizer binSecTokenizer = new StringTokenizer(binarySecToken, ".");

			binSecTokenizer.nextToken();

			String encodedJWT = binSecTokenizer.nextToken();

			jsonWebToken = new String(Base64.getDecoder().decode(encodedJWT.getBytes()));
		}

		return jsonWebToken;
	}

}
