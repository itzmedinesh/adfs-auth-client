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
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for anonymous complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 *  
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "requestSecurityToken"
})
@XmlRootElement(name = "Body")
public class Body {

    @XmlElement(name = "RequestSecurityToken", namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512", required = true)
    protected RequestSecurityToken requestSecurityToken;

    /**
     * Gets the value of the requestSecurityToken property.
     * 
     * @return
     *     possible object is
     *     {@link RequestSecurityToken }
     *     
     */
    public RequestSecurityToken getRequestSecurityToken() {
        return requestSecurityToken;
    }

    /**
     * Sets the value of the requestSecurityToken property.
     * 
     * @param value
     *     allowed object is
     *     {@link RequestSecurityToken }
     *     
     */
    public void setRequestSecurityToken(RequestSecurityToken value) {
        this.requestSecurityToken = value;
    }

}
