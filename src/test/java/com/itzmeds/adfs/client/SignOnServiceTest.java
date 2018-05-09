package com.itzmeds.adfs.client;

import java.util.Base64;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.itzmeds.adfs.client.SignOnService.TokenTypes;
import com.itzmeds.adfs.client.response.jwt.BinarySecurityToken;
import com.itzmeds.adfs.client.response.saml.RequestedSecurityToken.Assertion;
import com.itzmeds.adfs.client.response.saml.RequestedSecurityToken.Assertion.AttributeStatement.Attribute;

public class SignOnServiceTest {

	String TARGET_URL = "https://sts.test.com/adfs/services/trust/13/usernamemixed";

	String CLIENT_ADDRESS = "urn:test:colleague:tasksvcapi";

	SignOnService signOnService;

	@Before
	public void setup() {
		signOnService = new SignOnServiceImpl();
	}

	@Test
	public void testCreateSignOnRequest() throws SignOnException {

		String signOnReq = signOnService.createSignOnRequest("globaldev\\testuser", "testpass",
				TokenTypes.SAML_TOKEN_TYPE, TARGET_URL, CLIENT_ADDRESS);

		String expectedRequestXML = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><soap:Envelope xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Header><a:To>https://sts.test.com/adfs/services/trust/13/usernamemixed</a:To><wsse:Security><wsse:UsernameToken wsu:Id=\"UsernameToken-1\"><wsse:Username>globaldev\\testuser</wsse:Username><wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">testpass</wsse:Password></wsse:UsernameToken></wsse:Security><a:Action>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action></soap:Header><soap:Body><trust:RequestSecurityToken><wsp:AppliesTo><a:EndpointReference><a:Address>urn:test:colleague:tasksvcapi</a:Address></a:EndpointReference></wsp:AppliesTo><trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType><trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType><trust:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</trust:TokenType></trust:RequestSecurityToken></soap:Body></soap:Envelope>";

		Assert.assertNotNull(signOnReq);
		Assert.assertNotEquals(signOnReq, "");
		Assert.assertEquals(signOnReq, expectedRequestXML);

		signOnReq = signOnService.createSignOnRequest("globaldev\\testuser", "testpass", TokenTypes.JWT_TOKEN_TYPE,
				TARGET_URL, CLIENT_ADDRESS);

		expectedRequestXML = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><soap:Envelope xmlns:trust=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Header><a:To>https://sts.test.com/adfs/services/trust/13/usernamemixed</a:To><wsse:Security><wsse:UsernameToken wsu:Id=\"UsernameToken-1\"><wsse:Username>globaldev\\testuser</wsse:Username><wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">testpass</wsse:Password></wsse:UsernameToken></wsse:Security><a:Action>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action></soap:Header><soap:Body><trust:RequestSecurityToken><wsp:AppliesTo><a:EndpointReference><a:Address>urn:test:colleague:tasksvcapi</a:Address></a:EndpointReference></wsp:AppliesTo><trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType><trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType><trust:TokenType>urn:ietf:params:oauth:token-type:jwt</trust:TokenType></trust:RequestSecurityToken></soap:Body></soap:Envelope>";

		Assert.assertEquals(signOnReq, expectedRequestXML);
	}

	@Test
	public void testParseSignOnResponse() throws SignOnException {

		String response = "<s:Envelope>\n" + "<s:Header>\n"
				+ "<a:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal</a:Action>\n"
				+ "<o:Security s:mustUnderstand=\"1\">\n" + "<u:Timestamp u:Id=\"_0\">\n"
				+ "<u:Created>2018-03-19T07:09:02.738Z</u:Created>\n"
				+ "<u:Expires>2018-03-19T07:14:02.738Z</u:Expires>\n" + " </u:Timestamp>\n" + "</o:Security>\n"
				+ " </s:Header>\n" + "<s:Body>\n" + "<trust:RequestSecurityTokenResponseCollection>\n"
				+ "<trust:RequestSecurityTokenResponse>\n" + "<trust:Lifetime>\n"
				+ "<wsu:Created>2018-03-19T07:09:02.722Z</wsu:Created>\n"
				+ "<wsu:Expires>2018-03-19T08:09:02.722Z</wsu:Expires>\n" + " </trust:Lifetime>\n" + "<wsp:AppliesTo>\n"
				+ "<wsa:EndpointReference>\n" + "<wsa:Address>urn:test:colleague:tasksvcapi</wsa:Address>\n"
				+ "</wsa:EndpointReference>\n" + "</wsp:AppliesTo>\n" + "<trust:RequestedSecurityToken>\n"
				+ "<Assertion ID=\"_7a225b4b-e628-442f-8ee8-1a2b7c985ced\" IssueInstant=\"2018-03-19T07:09:02.738Z\" Version=\"2.0\">\n"
				+ "<Issuer>http://sts.test.com/adfs/services/trust</Issuer>\n" + "<ds:Signature></ds:Signature>\n"
				+ "<Subject>\n" + "<SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n"
				+ "<SubjectConfirmationData NotOnOrAfter=\"2018-03-19T07:14:02.738Z\" />\n" + "</SubjectConfirmation>\n"
				+ "</Subject>\n"
				+ "<Conditions NotBefore=\"2018-03-19T07:09:02.722Z\" NotOnOrAfter=\"2018-03-19T08:09:02.722Z\">\n"
				+ "<AudienceRestriction>\n" + "<Audience>urn:test:colleague:tasksvcapi</Audience>\n"
				+ "</AudienceRestriction>\n" + "</Conditions>\n" + "<AttributeStatement>\n"
				+ "<Attribute Name=\"FirstName\">\n" + "<AttributeValue>Dinesh</AttributeValue>\n" + "</Attribute>\n"
				+ "<Attribute Name=\"LastName\">\n" + "<AttributeValue>Subramanianx</AttributeValue>\n"
				+ "</Attribute>\n" + " </AttributeStatement>\n"
				+ "<AuthnStatement AuthnInstant=\"2018-03-19T07:09:02.707Z\">\n" + "<AuthnContext>\n"
				+ "<AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>\n"
				+ "</AuthnContext>\n" + "</AuthnStatement>\n" + " </Assertion>\n" + "</trust:RequestedSecurityToken>\n"
				+ "<trust:RequestedAttachedReference>\n"
				+ "<SecurityTokenReference b:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0\">\n"
				+ "<KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID\">_7a225b4b-e628-442f-8ee8-1a2b7c985ced</KeyIdentifier>\n"
				+ "</SecurityTokenReference>\n" + "</trust:RequestedAttachedReference>\n"
				+ "<trust:RequestedUnattachedReference>\n"
				+ "<SecurityTokenReference b:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0\">\n"
				+ "<KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID\">_7a225b4b-e628-442f-8ee8-1a2b7c985ced</KeyIdentifier>\n"
				+ "</SecurityTokenReference>\n" + "</trust:RequestedUnattachedReference>\n"
				+ "<trust:TokenType>urn:oasis:names:tc:SAML:2.0:assertion</trust:TokenType>\n"
				+ "<trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>\n"
				+ "<trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType>\n"
				+ " </trust:RequestSecurityTokenResponse>\n" + "</trust:RequestSecurityTokenResponseCollection>\n"
				+ "</s:Body>\n" + " </s:Envelope>";

		Assertion samlAssertion = signOnService.getSamlToken(response);

		Assert.assertNotNull(samlAssertion);

		String userFirstName = null;
		String userLastName = null;

		for (Attribute attr : samlAssertion.getAttributeStatement().getAttribute()) {
			if (attr.getName().equals("FirstName"))
				userFirstName = attr.getAttributeValue();
			else if (attr.getName().equals("LastName"))
				userLastName = attr.getAttributeValue();
		}

		Assert.assertEquals(userFirstName, "Dinesh");
		Assert.assertEquals(userLastName, "Subramanianx");
	}

	@Test
	public void testParseSignOnResponseBst() throws SignOnException {

		String response = "<s:Envelope>\n" + "<s:Header>\n"
				+ "<a:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal</a:Action>\n"
				+ "<o:Security s:mustUnderstand=\"1\">\n" + "<u:Timestamp u:Id=\"_0\">\n"
				+ "<u:Created>2018-03-19T13:31:36.966Z</u:Created>\n"
				+ "<u:Expires>2018-03-19T13:36:36.966Z</u:Expires>\n" + " </u:Timestamp>\n" + "</o:Security>\n"
				+ " </s:Header>\n" + "<s:Body>\n" + "<trust:RequestSecurityTokenResponseCollection>\n"
				+ "<trust:RequestSecurityTokenResponse>\n" + "<trust:Lifetime>\n"
				+ "<wsu:Created>2018-03-19T13:31:36.856Z</wsu:Created>\n"
				+ "<wsu:Expires>2018-03-19T14:31:36.856Z</wsu:Expires>\n" + " </trust:Lifetime>\n" + "<wsp:AppliesTo>\n"
				+ "<wsa:EndpointReference>\n" + "<wsa:Address>urn:test:colleague:tasksvcapi</wsa:Address>\n"
				+ "</wsa:EndpointReference>\n" + "</wsp:AppliesTo>\n" + "<trust:RequestedSecurityToken>\n"
				+ "<wsse:BinarySecurityToken wsu:Id=\"_a0e46a43-d1a2-4121-90c5-1c7a2efd03d1-CF4F5D07CE9C497E54341482731B54E4\" ValueType=\"urn:ietf:params:oauth:token-type:jwt\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1V6STFOaUlzSW5nMWRDSTZJbmhUWTNCNU9ESmZiRzVUVnpCWlJtcDNUV2hmV0VoelMzSkVPQ0o5LmV5SmhkV1FpT2lKMWNtNDZkR1Z6ZERwamIyeHNaV0ZuZFdVNmRHRnphM04yWTJGd2FTSXNJbWx6Y3lJNkltaDBkSEE2THk5emRITXVkR1Z6ZEM1amIyMHZZV1JtY3k5elpYSjJhV05sY3k5MGNuVnpkQ0lzSW1saGRDSTZNVFV5TVRRMk5qSTVOaXdpWlhod0lqb3hOVEl4TkRZNU9EazJMQ0pHYVhKemRFNWhiV1VpT2lKRWFXNWxjMmdpTENKTVlYTjBUbUZ0WlNJNklsTjFZbkpoYldGdWFXRnVlQ0lzSW1GMWRHaHRaWFJvYjJRaU9pSm9kSFJ3T2k4dmMyTm9aVzFoY3k1dGFXTnliM052Wm5RdVkyOXRMM2R6THpJd01EZ3ZNRFl2YVdSbGJuUnBkSGt2WVhWMGFHVnVkR2xqWVhScGIyNXRaWFJvYjJRdmNHRnpjM2R2Y21RaUxDSmhkWFJvWDNScGJXVWlPaUl5TURFNExUQXpMVEU1VkRFek9qTXhPak0yTGpneU5Wb2lMQ0oyWlhJaU9pSXhMakFpZlE9PS5zeFpHQnNMbFZ0SGpYVUJWRUZ6N2xxRkJ4d3VjTjNKWmxrRHg0RU9VNWdXUDlOai1JdG84TG5IZDFEOURMdFVOLXJmMThLcTVZbFBlTzdNTFNGbm44eWN2NElja2ItdDdfTURDVDFYQVVCNUxsMVZ1b2VZaHdlak4zSmc0RTBuT2hIY2hscGdPb0lyLV9qSk9sQVRVLVZXR0ZRMjdVTmNURmNZVHVSVHJfQmhfUnBQeDQwQnZNS2xmOUo1QkRnZDJRa0Exa2wzRVVlQ1hGQ05PTUg1NGZjb3huZXRVSXg4UnlmWHhva01adTR1ZzJ0V1VIbUg3RkZxejMxU3RZNEFXaVZTeFFzcjR5aFdOY2NHNGVZNmZ0elk5YjlycDhIQ1VJTXJ4RFlUOExNQ0NWVk1DbkpWcWJxcXpObDdSMks5Yk5uay1mcjhYanoyQ2hKdmxNdVR4Q2c=</wsse:BinarySecurityToken>\n"
				+ "</trust:RequestedSecurityToken>\n"
				+ "<trust:TokenType>urn:ietf:params:oauth:token-type:jwt</trust:TokenType>\n"
				+ "<trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>\n"
				+ "<trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType>\n"
				+ " </trust:RequestSecurityTokenResponse>\n" + "</trust:RequestSecurityTokenResponseCollection>\n"
				+ "</s:Body>\n" + " </s:Envelope>";

		BinarySecurityToken bst = signOnService.getBinarySecurityToken(response);

		String expectedEncodedToken = "ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1V6STFOaUlzSW5nMWRDSTZJbmhUWTNCNU9ESmZiRzVUVnpCWlJtcDNUV2hmV0VoelMzSkVPQ0o5LmV5SmhkV1FpT2lKMWNtNDZkR1Z6ZERwamIyeHNaV0ZuZFdVNmRHRnphM04yWTJGd2FTSXNJbWx6Y3lJNkltaDBkSEE2THk5emRITXVkR1Z6ZEM1amIyMHZZV1JtY3k5elpYSjJhV05sY3k5MGNuVnpkQ0lzSW1saGRDSTZNVFV5TVRRMk5qSTVOaXdpWlhod0lqb3hOVEl4TkRZNU9EazJMQ0pHYVhKemRFNWhiV1VpT2lKRWFXNWxjMmdpTENKTVlYTjBUbUZ0WlNJNklsTjFZbkpoYldGdWFXRnVlQ0lzSW1GMWRHaHRaWFJvYjJRaU9pSm9kSFJ3T2k4dmMyTm9aVzFoY3k1dGFXTnliM052Wm5RdVkyOXRMM2R6THpJd01EZ3ZNRFl2YVdSbGJuUnBkSGt2WVhWMGFHVnVkR2xqWVhScGIyNXRaWFJvYjJRdmNHRnpjM2R2Y21RaUxDSmhkWFJvWDNScGJXVWlPaUl5TURFNExUQXpMVEU1VkRFek9qTXhPak0yTGpneU5Wb2lMQ0oyWlhJaU9pSXhMakFpZlE9PS5zeFpHQnNMbFZ0SGpYVUJWRUZ6N2xxRkJ4d3VjTjNKWmxrRHg0RU9VNWdXUDlOai1JdG84TG5IZDFEOURMdFVOLXJmMThLcTVZbFBlTzdNTFNGbm44eWN2NElja2ItdDdfTURDVDFYQVVCNUxsMVZ1b2VZaHdlak4zSmc0RTBuT2hIY2hscGdPb0lyLV9qSk9sQVRVLVZXR0ZRMjdVTmNURmNZVHVSVHJfQmhfUnBQeDQwQnZNS2xmOUo1QkRnZDJRa0Exa2wzRVVlQ1hGQ05PTUg1NGZjb3huZXRVSXg4UnlmWHhva01adTR1ZzJ0V1VIbUg3RkZxejMxU3RZNEFXaVZTeFFzcjR5aFdOY2NHNGVZNmZ0elk5YjlycDhIQ1VJTXJ4RFlUOExNQ0NWVk1DbkpWcWJxcXpObDdSMks5Yk5uay1mcjhYanoyQ2hKdmxNdVR4Q2c=";

		byte[] actualEncodedToken = Base64.getEncoder().encode(bst.getValue());

		Assert.assertEquals(expectedEncodedToken, new String(actualEncodedToken));

	}

	@Test
	public void testParseSignOnResponseJwt() throws SignOnException {

		String response = "<s:Envelope>\n" + "<s:Header>\n"
				+ "<a:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTRC/IssueFinal</a:Action>\n"
				+ "<o:Security s:mustUnderstand=\"1\">\n" + "<u:Timestamp u:Id=\"_0\">\n"
				+ "<u:Created>2018-03-19T13:31:36.966Z</u:Created>\n"
				+ "<u:Expires>2018-03-19T13:36:36.966Z</u:Expires>\n" + " </u:Timestamp>\n" + "</o:Security>\n"
				+ " </s:Header>\n" + "<s:Body>\n" + "<trust:RequestSecurityTokenResponseCollection>\n"
				+ "<trust:RequestSecurityTokenResponse>\n" + "<trust:Lifetime>\n"
				+ "<wsu:Created>2018-03-19T13:31:36.856Z</wsu:Created>\n"
				+ "<wsu:Expires>2018-03-19T14:31:36.856Z</wsu:Expires>\n" + " </trust:Lifetime>\n" + "<wsp:AppliesTo>\n"
				+ "<wsa:EndpointReference>\n" + "<wsa:Address>urn:test:colleague:tasksvcapi</wsa:Address>\n"
				+ "</wsa:EndpointReference>\n" + "</wsp:AppliesTo>\n" + "<trust:RequestedSecurityToken>\n"
				+ "<wsse:BinarySecurityToken wsu:Id=\"_a0e46a43-d1a2-4121-90c5-1c7a2efd03d1-CF4F5D07CE9C497E54341482731B54E4\" ValueType=\"urn:ietf:params:oauth:token-type:jwt\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1V6STFOaUlzSW5nMWRDSTZJbmhUWTNCNU9ESmZiRzVUVnpCWlJtcDNUV2hmV0VoelMzSkVPQ0o5LmV5SmhkV1FpT2lKMWNtNDZkR1Z6ZERwamIyeHNaV0ZuZFdVNmRHRnphM04yWTJGd2FTSXNJbWx6Y3lJNkltaDBkSEE2THk5emRITXVkR1Z6ZEM1amIyMHZZV1JtY3k5elpYSjJhV05sY3k5MGNuVnpkQ0lzSW1saGRDSTZNVFV5TVRRMk5qSTVOaXdpWlhod0lqb3hOVEl4TkRZNU9EazJMQ0pHYVhKemRFNWhiV1VpT2lKRWFXNWxjMmdpTENKTVlYTjBUbUZ0WlNJNklsTjFZbkpoYldGdWFXRnVlQ0lzSW1GMWRHaHRaWFJvYjJRaU9pSm9kSFJ3T2k4dmMyTm9aVzFoY3k1dGFXTnliM052Wm5RdVkyOXRMM2R6THpJd01EZ3ZNRFl2YVdSbGJuUnBkSGt2WVhWMGFHVnVkR2xqWVhScGIyNXRaWFJvYjJRdmNHRnpjM2R2Y21RaUxDSmhkWFJvWDNScGJXVWlPaUl5TURFNExUQXpMVEU1VkRFek9qTXhPak0yTGpneU5Wb2lMQ0oyWlhJaU9pSXhMakFpZlE9PS5zeFpHQnNMbFZ0SGpYVUJWRUZ6N2xxRkJ4d3VjTjNKWmxrRHg0RU9VNWdXUDlOai1JdG84TG5IZDFEOURMdFVOLXJmMThLcTVZbFBlTzdNTFNGbm44eWN2NElja2ItdDdfTURDVDFYQVVCNUxsMVZ1b2VZaHdlak4zSmc0RTBuT2hIY2hscGdPb0lyLV9qSk9sQVRVLVZXR0ZRMjdVTmNURmNZVHVSVHJfQmhfUnBQeDQwQnZNS2xmOUo1QkRnZDJRa0Exa2wzRVVlQ1hGQ05PTUg1NGZjb3huZXRVSXg4UnlmWHhva01adTR1ZzJ0V1VIbUg3RkZxejMxU3RZNEFXaVZTeFFzcjR5aFdOY2NHNGVZNmZ0elk5YjlycDhIQ1VJTXJ4RFlUOExNQ0NWVk1DbkpWcWJxcXpObDdSMks5Yk5uay1mcjhYanoyQ2hKdmxNdVR4Q2c=</wsse:BinarySecurityToken>\n"
				+ "</trust:RequestedSecurityToken>\n"
				+ "<trust:TokenType>urn:ietf:params:oauth:token-type:jwt</trust:TokenType>\n"
				+ "<trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>\n"
				+ "<trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType>\n"
				+ " </trust:RequestSecurityTokenResponse>\n" + "</trust:RequestSecurityTokenResponseCollection>\n"
				+ "</s:Body>\n" + " </s:Envelope>";

		String actualJwt = signOnService.getJsonWebToken(response);

		System.out.println(actualJwt);

		String expectedJwt = "{\"aud\":\"urn:test:colleague:tasksvcapi\",\"iss\":\"http://sts.test.com/adfs/services/trust\",\"iat\":1521466296,\"exp\":1521469896,\"FirstName\":\"Dinesh\",\"LastName\":\"Subramanianx\",\"authmethod\":\"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password\",\"auth_time\":\"2018-03-19T13:31:36.825Z\",\"ver\":\"1.0\"}";

		Assert.assertEquals(expectedJwt, actualJwt);

	}

}
