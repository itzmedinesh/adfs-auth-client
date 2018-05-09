//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.03.20 at 12:43:08 PM IST 
//

package com.itzmeds.adfs.client.response.saml;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.datatype.XMLGregorianCalendar;

/**
 * <p>
 * Java class for anonymous complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within
 * this class.
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "assertion" })
@XmlRootElement(name = "RequestedSecurityToken", namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512")
public class RequestedSecurityToken {

	@XmlElement(name = "Assertion", required = true)
	protected RequestedSecurityToken.Assertion assertion;

	/**
	 * Gets the value of the assertion property.
	 * 
	 * @return possible object is {@link RequestedSecurityToken.Assertion }
	 * 
	 */
	public RequestedSecurityToken.Assertion getAssertion() {
		return assertion;
	}

	/**
	 * Sets the value of the assertion property.
	 * 
	 * @param value
	 *            allowed object is {@link RequestedSecurityToken.Assertion }
	 * 
	 */
	public void setAssertion(RequestedSecurityToken.Assertion value) {
		this.assertion = value;
	}

	/**
	 * <p>
	 * Java class for anonymous complex type.
	 * 
	 */
	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = { "issuer", "signature", "subject", "conditions", "attributeStatement",
			"authnStatement" })
	public static class Assertion {

		@XmlElement(name = "Issuer", required = true)
		@XmlSchemaType(name = "anyURI")
		protected String issuer;
		@XmlElement(name = "Signature", namespace = "http://www.w3.org/2000/09/xmldsig#", required = true)
		protected Signature signature;
		@XmlElement(name = "Subject", required = true)
		protected RequestedSecurityToken.Assertion.Subject subject;
		@XmlElement(name = "Conditions", required = true)
		protected RequestedSecurityToken.Assertion.Conditions conditions;
		@XmlElement(name = "AttributeStatement", required = true)
		protected RequestedSecurityToken.Assertion.AttributeStatement attributeStatement;
		@XmlElement(name = "AuthnStatement", required = true)
		protected RequestedSecurityToken.Assertion.AuthnStatement authnStatement;
		@XmlAttribute(name = "ID", required = true)
		@XmlSchemaType(name = "anySimpleType")
		protected String id;
		@XmlAttribute(name = "IssueInstant", required = true)
		@XmlSchemaType(name = "dateTime")
		protected XMLGregorianCalendar issueInstant;
		@XmlAttribute(name = "Version", required = true)
		protected BigDecimal version;

		/**
		 * Gets the value of the issuer property.
		 * 
		 * @return possible object is {@link String }
		 * 
		 */
		public String getIssuer() {
			return issuer;
		}

		/**
		 * Sets the value of the issuer property.
		 * 
		 * @param value
		 *            allowed object is {@link String }
		 * 
		 */
		public void setIssuer(String value) {
			this.issuer = value;
		}

		/**
		 * Gets the value of the signature property.
		 * 
		 * @return possible object is {@link Signature }
		 * 
		 */
		public Signature getSignature() {
			return signature;
		}

		/**
		 * Sets the value of the signature property.
		 * 
		 * @param value
		 *            allowed object is {@link Signature }
		 * 
		 */
		public void setSignature(Signature value) {
			this.signature = value;
		}

		/**
		 * Gets the value of the subject property.
		 * 
		 * @return possible object is {@link RequestedSecurityToken.Assertion.Subject }
		 * 
		 */
		public RequestedSecurityToken.Assertion.Subject getSubject() {
			return subject;
		}

		/**
		 * Sets the value of the subject property.
		 * 
		 * @param value
		 *            allowed object is
		 *            {@link RequestedSecurityToken.Assertion.Subject }
		 * 
		 */
		public void setSubject(RequestedSecurityToken.Assertion.Subject value) {
			this.subject = value;
		}

		/**
		 * Gets the value of the conditions property.
		 * 
		 * @return possible object is
		 *         {@link RequestedSecurityToken.Assertion.Conditions }
		 * 
		 */
		public RequestedSecurityToken.Assertion.Conditions getConditions() {
			return conditions;
		}

		/**
		 * Sets the value of the conditions property.
		 * 
		 * @param value
		 *            allowed object is
		 *            {@link RequestedSecurityToken.Assertion.Conditions }
		 * 
		 */
		public void setConditions(RequestedSecurityToken.Assertion.Conditions value) {
			this.conditions = value;
		}

		/**
		 * Gets the value of the attributeStatement property.
		 * 
		 * @return possible object is
		 *         {@link RequestedSecurityToken.Assertion.AttributeStatement }
		 * 
		 */
		public RequestedSecurityToken.Assertion.AttributeStatement getAttributeStatement() {
			return attributeStatement;
		}

		/**
		 * Sets the value of the attributeStatement property.
		 * 
		 * @param value
		 *            allowed object is
		 *            {@link RequestedSecurityToken.Assertion.AttributeStatement }
		 * 
		 */
		public void setAttributeStatement(RequestedSecurityToken.Assertion.AttributeStatement value) {
			this.attributeStatement = value;
		}

		/**
		 * Gets the value of the authnStatement property.
		 * 
		 * @return possible object is
		 *         {@link RequestedSecurityToken.Assertion.AuthnStatement }
		 * 
		 */
		public RequestedSecurityToken.Assertion.AuthnStatement getAuthnStatement() {
			return authnStatement;
		}

		/**
		 * Sets the value of the authnStatement property.
		 * 
		 * @param value
		 *            allowed object is
		 *            {@link RequestedSecurityToken.Assertion.AuthnStatement }
		 * 
		 */
		public void setAuthnStatement(RequestedSecurityToken.Assertion.AuthnStatement value) {
			this.authnStatement = value;
		}

		/**
		 * Gets the value of the id property.
		 * 
		 * @return possible object is {@link String }
		 * 
		 */
		public String getID() {
			return id;
		}

		/**
		 * Sets the value of the id property.
		 * 
		 * @param value
		 *            allowed object is {@link String }
		 * 
		 */
		public void setID(String value) {
			this.id = value;
		}

		/**
		 * Gets the value of the issueInstant property.
		 * 
		 * @return possible object is {@link XMLGregorianCalendar }
		 * 
		 */
		public XMLGregorianCalendar getIssueInstant() {
			return issueInstant;
		}

		/**
		 * Sets the value of the issueInstant property.
		 * 
		 * @param value
		 *            allowed object is {@link XMLGregorianCalendar }
		 * 
		 */
		public void setIssueInstant(XMLGregorianCalendar value) {
			this.issueInstant = value;
		}

		/**
		 * Gets the value of the version property.
		 * 
		 * @return possible object is {@link BigDecimal }
		 * 
		 */
		public BigDecimal getVersion() {
			return version;
		}

		/**
		 * Sets the value of the version property.
		 * 
		 * @param value
		 *            allowed object is {@link BigDecimal }
		 * 
		 */
		public void setVersion(BigDecimal value) {
			this.version = value;
		}



		/**
		 * <p>
		 * Java class for anonymous complex type.
		 * 
		 */
		@XmlAccessorType(XmlAccessType.FIELD)
		@XmlType(name = "", propOrder = { "attribute" })
		public static class AttributeStatement {

			@XmlElement(name = "Attribute", required = true)
			protected List<RequestedSecurityToken.Assertion.AttributeStatement.Attribute> attribute;

			/**
			 * Gets the value of the attribute property.
			 * 
			 * <p>
			 * This accessor method returns a reference to the live list, not a snapshot.
			 * Therefore any modification you make to the returned list will be present
			 * inside the JAXB object. This is why there is not a <CODE>set</CODE> method
			 * for the attribute property.
			 * 
			 * <p>
			 * For example, to add a new item, do as follows:
			 * 
			 * <pre>
			 * getAttribute().add(newItem);
			 * </pre>
			 * 
			 * 
			 * <p>
			 * Objects of the following type(s) are allowed in the list
			 * {@link RequestedSecurityToken.Assertion.AttributeStatement.Attribute }
			 * 
			 * 
			 */
			public List<RequestedSecurityToken.Assertion.AttributeStatement.Attribute> getAttribute() {
				if (attribute == null) {
					attribute = new ArrayList<RequestedSecurityToken.Assertion.AttributeStatement.Attribute>();
				}
				return this.attribute;
			}

			/**
			 * <p>
			 * Java class for anonymous complex type.
			 * 
			 */
			@XmlAccessorType(XmlAccessType.FIELD)
			@XmlType(name = "", propOrder = { "attributeValue" })
			public static class Attribute {

				@XmlElement(name = "AttributeValue", required = true)
				@XmlJavaTypeAdapter(CollapsedStringAdapter.class)
				@XmlSchemaType(name = "NCName")
				protected String attributeValue;
				@XmlAttribute(name = "Name", required = true)
				@XmlJavaTypeAdapter(CollapsedStringAdapter.class)
				@XmlSchemaType(name = "NCName")
				protected String name;

				/**
				 * Gets the value of the attributeValue property.
				 * 
				 * @return possible object is {@link String }
				 * 
				 */
				public String getAttributeValue() {
					return attributeValue;
				}

				/**
				 * Sets the value of the attributeValue property.
				 * 
				 * @param value
				 *            allowed object is {@link String }
				 * 
				 */
				public void setAttributeValue(String value) {
					this.attributeValue = value;
				}

				/**
				 * Gets the value of the name property.
				 * 
				 * @return possible object is {@link String }
				 * 
				 */
				public String getName() {
					return name;
				}

				/**
				 * Sets the value of the name property.
				 * 
				 * @param value
				 *            allowed object is {@link String }
				 * 
				 */
				public void setName(String value) {
					this.name = value;
				}

				@Override
				public String toString() {
					return "Attribute [attributeValue=" + attributeValue + ", name=" + name + "]";
				}

			}

			@Override
			public String toString() {
				return "AttributeStatement [attribute=" + attribute + "]";
			}

		}

		/**
		 * <p>
		 * Java class for anonymous complex type.
		 * 
		 */
		@XmlAccessorType(XmlAccessType.FIELD)
		@XmlType(name = "", propOrder = { "authnContext" })
		public static class AuthnStatement {

			@XmlElement(name = "AuthnContext", required = true)
			protected RequestedSecurityToken.Assertion.AuthnStatement.AuthnContext authnContext;
			@XmlAttribute(name = "AuthnInstant", required = true)
			@XmlSchemaType(name = "dateTime")
			protected XMLGregorianCalendar authnInstant;

			/**
			 * Gets the value of the authnContext property.
			 * 
			 * @return possible object is
			 *         {@link RequestedSecurityToken.Assertion.AuthnStatement.AuthnContext }
			 * 
			 */
			public RequestedSecurityToken.Assertion.AuthnStatement.AuthnContext getAuthnContext() {
				return authnContext;
			}

			/**
			 * Sets the value of the authnContext property.
			 * 
			 * @param value
			 *            allowed object is
			 *            {@link RequestedSecurityToken.Assertion.AuthnStatement.AuthnContext }
			 * 
			 */
			public void setAuthnContext(RequestedSecurityToken.Assertion.AuthnStatement.AuthnContext value) {
				this.authnContext = value;
			}

			/**
			 * Gets the value of the authnInstant property.
			 * 
			 * @return possible object is {@link XMLGregorianCalendar }
			 * 
			 */
			public XMLGregorianCalendar getAuthnInstant() {
				return authnInstant;
			}

			/**
			 * Sets the value of the authnInstant property.
			 * 
			 * @param value
			 *            allowed object is {@link XMLGregorianCalendar }
			 * 
			 */
			public void setAuthnInstant(XMLGregorianCalendar value) {
				this.authnInstant = value;
			}

			/**
			 * <p>
			 * Java class for anonymous complex type.
			 * 
			 */
			@XmlAccessorType(XmlAccessType.FIELD)
			@XmlType(name = "", propOrder = { "authnContextClassRef" })
			public static class AuthnContext {

				@XmlElement(name = "AuthnContextClassRef", required = true)
				@XmlSchemaType(name = "anyURI")
				protected String authnContextClassRef;

				/**
				 * Gets the value of the authnContextClassRef property.
				 * 
				 * @return possible object is {@link String }
				 * 
				 */
				public String getAuthnContextClassRef() {
					return authnContextClassRef;
				}

				/**
				 * Sets the value of the authnContextClassRef property.
				 * 
				 * @param value
				 *            allowed object is {@link String }
				 * 
				 */
				public void setAuthnContextClassRef(String value) {
					this.authnContextClassRef = value;
				}

				@Override
				public String toString() {
					return "AuthnContext [authnContextClassRef=" + authnContextClassRef + "]";
				}

			}

			@Override
			public String toString() {
				return "AuthnStatement [authnContext=" + authnContext + ", authnInstant=" + authnInstant + "]";
			}

		}

		/**
		 * <p>
		 * Java class for anonymous complex type.
		 * 
		 */
		@XmlAccessorType(XmlAccessType.FIELD)
		@XmlType(name = "", propOrder = { "audienceRestriction" })
		public static class Conditions {

			@XmlElement(name = "AudienceRestriction", required = true)
			protected RequestedSecurityToken.Assertion.Conditions.AudienceRestriction audienceRestriction;
			@XmlAttribute(name = "NotBefore", required = true)
			@XmlSchemaType(name = "dateTime")
			protected XMLGregorianCalendar notBefore;
			@XmlAttribute(name = "NotOnOrAfter", required = true)
			@XmlSchemaType(name = "dateTime")
			protected XMLGregorianCalendar notOnOrAfter;

			/**
			 * Gets the value of the audienceRestriction property.
			 * 
			 * @return possible object is
			 *         {@link RequestedSecurityToken.Assertion.Conditions.AudienceRestriction }
			 * 
			 */
			public RequestedSecurityToken.Assertion.Conditions.AudienceRestriction getAudienceRestriction() {
				return audienceRestriction;
			}

			/**
			 * Sets the value of the audienceRestriction property.
			 * 
			 * @param value
			 *            allowed object is
			 *            {@link RequestedSecurityToken.Assertion.Conditions.AudienceRestriction }
			 * 
			 */
			public void setAudienceRestriction(RequestedSecurityToken.Assertion.Conditions.AudienceRestriction value) {
				this.audienceRestriction = value;
			}

			/**
			 * Gets the value of the notBefore property.
			 * 
			 * @return possible object is {@link XMLGregorianCalendar }
			 * 
			 */
			public XMLGregorianCalendar getNotBefore() {
				return notBefore;
			}

			/**
			 * Sets the value of the notBefore property.
			 * 
			 * @param value
			 *            allowed object is {@link XMLGregorianCalendar }
			 * 
			 */
			public void setNotBefore(XMLGregorianCalendar value) {
				this.notBefore = value;
			}

			/**
			 * Gets the value of the notOnOrAfter property.
			 * 
			 * @return possible object is {@link XMLGregorianCalendar }
			 * 
			 */
			public XMLGregorianCalendar getNotOnOrAfter() {
				return notOnOrAfter;
			}

			/**
			 * Sets the value of the notOnOrAfter property.
			 * 
			 * @param value
			 *            allowed object is {@link XMLGregorianCalendar }
			 * 
			 */
			public void setNotOnOrAfter(XMLGregorianCalendar value) {
				this.notOnOrAfter = value;
			}

			/**
			 * <p>
			 * Java class for anonymous complex type.
			 * 
			 */
			@XmlAccessorType(XmlAccessType.FIELD)
			@XmlType(name = "", propOrder = { "audience" })
			public static class AudienceRestriction {

				@XmlElement(name = "Audience", required = true)
				@XmlJavaTypeAdapter(CollapsedStringAdapter.class)
				@XmlSchemaType(name = "NMTOKEN")
				protected String audience;

				/**
				 * Gets the value of the audience property.
				 * 
				 * @return possible object is {@link String }
				 * 
				 */
				public String getAudience() {
					return audience;
				}

				/**
				 * Sets the value of the audience property.
				 * 
				 * @param value
				 *            allowed object is {@link String }
				 * 
				 */
				public void setAudience(String value) {
					this.audience = value;
				}

				@Override
				public String toString() {
					return "AudienceRestriction [audience=" + audience + "]";
				}

			}

			@Override
			public String toString() {
				return "Conditions [audienceRestriction=" + audienceRestriction + ", notBefore=" + notBefore
						+ ", notOnOrAfter=" + notOnOrAfter + "]";
			}

		}

		/**
		 * <p>
		 * Java class for anonymous complex type.
		 * 
		 */
		@XmlAccessorType(XmlAccessType.FIELD)
		@XmlType(name = "", propOrder = { "subjectConfirmation" })
		public static class Subject {

			@XmlElement(name = "SubjectConfirmation", required = true)
			protected RequestedSecurityToken.Assertion.Subject.SubjectConfirmation subjectConfirmation;

			/**
			 * Gets the value of the subjectConfirmation property.
			 * 
			 * @return possible object is
			 *         {@link RequestedSecurityToken.Assertion.Subject.SubjectConfirmation }
			 * 
			 */
			public RequestedSecurityToken.Assertion.Subject.SubjectConfirmation getSubjectConfirmation() {
				return subjectConfirmation;
			}

			/**
			 * Sets the value of the subjectConfirmation property.
			 * 
			 * @param value
			 *            allowed object is
			 *            {@link RequestedSecurityToken.Assertion.Subject.SubjectConfirmation }
			 * 
			 */
			public void setSubjectConfirmation(RequestedSecurityToken.Assertion.Subject.SubjectConfirmation value) {
				this.subjectConfirmation = value;
			}

			/**
			 * <p>
			 * Java class for anonymous complex type.
			 * 
			 */
			@XmlAccessorType(XmlAccessType.FIELD)
			@XmlType(name = "", propOrder = { "subjectConfirmationData" })
			public static class SubjectConfirmation {

				@XmlElement(name = "SubjectConfirmationData", required = true)
				protected RequestedSecurityToken.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData subjectConfirmationData;
				@XmlAttribute(name = "Method", required = true)
				@XmlSchemaType(name = "anyURI")
				protected String method;

				/**
				 * Gets the value of the subjectConfirmationData property.
				 * 
				 * @return possible object is
				 *         {@link RequestedSecurityToken.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData }
				 * 
				 */
				public RequestedSecurityToken.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData getSubjectConfirmationData() {
					return subjectConfirmationData;
				}

				/**
				 * Sets the value of the subjectConfirmationData property.
				 * 
				 * @param value
				 *            allowed object is
				 *            {@link RequestedSecurityToken.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData }
				 * 
				 */
				public void setSubjectConfirmationData(
						RequestedSecurityToken.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData value) {
					this.subjectConfirmationData = value;
				}

				/**
				 * Gets the value of the method property.
				 * 
				 * @return possible object is {@link String }
				 * 
				 */
				public String getMethod() {
					return method;
				}

				/**
				 * Sets the value of the method property.
				 * 
				 * @param value
				 *            allowed object is {@link String }
				 * 
				 */
				public void setMethod(String value) {
					this.method = value;
				}

				/**
				 * <p>
				 * Java class for anonymous complex type. 
				 * 
				 */
				@XmlAccessorType(XmlAccessType.FIELD)
				@XmlType(name = "")
				public static class SubjectConfirmationData {

					@XmlAttribute(name = "NotOnOrAfter", required = true)
					@XmlSchemaType(name = "dateTime")
					protected XMLGregorianCalendar notOnOrAfter;

					/**
					 * Gets the value of the notOnOrAfter property.
					 * 
					 * @return possible object is {@link XMLGregorianCalendar }
					 * 
					 */
					public XMLGregorianCalendar getNotOnOrAfter() {
						return notOnOrAfter;
					}

					/**
					 * Sets the value of the notOnOrAfter property.
					 * 
					 * @param value
					 *            allowed object is {@link XMLGregorianCalendar }
					 * 
					 */
					public void setNotOnOrAfter(XMLGregorianCalendar value) {
						this.notOnOrAfter = value;
					}

					@Override
					public String toString() {
						return "SubjectConfirmationData [notOnOrAfter=" + notOnOrAfter + "]";
					}

				}

			}

			@Override
			public String toString() {
				return "Subject [subjectConfirmation=" + subjectConfirmation + "]";
			}

		}

		@Override
		public String toString() {
			return "Assertion [issuer=" + issuer + ", signature=" + signature + ", subject=" + subject + ", conditions="
					+ conditions + ", attributeStatement=" + attributeStatement + ", authnStatement=" + authnStatement
					+ ", id=" + id + ", issueInstant=" + issueInstant + ", version=" + version + "]";
		}

	}

}
