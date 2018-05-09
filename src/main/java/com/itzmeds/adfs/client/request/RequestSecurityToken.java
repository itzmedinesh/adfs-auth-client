//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.03.16 at 07:26:35 PM IST 
//


package com.itzmeds.adfs.client.request;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 *  
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "appliesTo",
    "keyType",
    "requestType",
    "tokenType"
})
@XmlRootElement(name = "RequestSecurityToken", namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512")
public class RequestSecurityToken {

    @XmlElement(name = "AppliesTo", namespace = "http://schemas.xmlsoap.org/ws/2004/09/policy", required = true)
    protected AppliesTo appliesTo;
    @XmlElement(name = "KeyType", namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String keyType;
    @XmlElement(name = "RequestType", namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String requestType;
    @XmlElement(name = "TokenType", namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String tokenType;

    /**
     * Gets the value of the appliesTo property.
     * 
     * @return
     *     possible object is
     *     {@link AppliesTo }
     *     
     */
    public AppliesTo getAppliesTo() {
        return appliesTo;
    }

    /**
     * Sets the value of the appliesTo property.
     * 
     * @param value
     *     allowed object is
     *     {@link AppliesTo }
     *     
     */
    public void setAppliesTo(AppliesTo value) {
        this.appliesTo = value;
    }

    /**
     * Gets the value of the keyType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKeyType() {
        return keyType;
    }

    /**
     * Sets the value of the keyType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKeyType(String value) {
        this.keyType = value;
    }

    /**
     * Gets the value of the requestType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRequestType() {
        return requestType;
    }

    /**
     * Sets the value of the requestType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRequestType(String value) {
        this.requestType = value;
    }

    /**
     * Gets the value of the tokenType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTokenType() {
        return tokenType;
    }

    /**
     * Sets the value of the tokenType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTokenType(String value) {
        this.tokenType = value;
    }

}
