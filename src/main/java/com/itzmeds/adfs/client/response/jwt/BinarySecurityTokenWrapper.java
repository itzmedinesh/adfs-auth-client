//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.03.19 at 09:00:41 PM IST 
//


package com.itzmeds.adfs.client.response.jwt;

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
 * <pre>
 * &lt;complexType>
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "binarySecurityToken"
})
@XmlRootElement(name = "RequestedSecurityToken")
public class BinarySecurityTokenWrapper {

    @XmlElement(name = "BinarySecurityToken", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", required = true)
    protected BinarySecurityToken binarySecurityToken;

    /**
     * Gets the value of the binarySecurityToken property.
     * 
     * @return
     *     possible object is
     *     {@link BinarySecurityToken }
     *     
     */
    public BinarySecurityToken getBinarySecurityToken() {
        return binarySecurityToken;
    }

    /**
     * Sets the value of the binarySecurityToken property.
     * 
     * @param value
     *     allowed object is
     *     {@link BinarySecurityToken }
     *     
     */
    public void setBinarySecurityToken(BinarySecurityToken value) {
        this.binarySecurityToken = value;
    }

}
