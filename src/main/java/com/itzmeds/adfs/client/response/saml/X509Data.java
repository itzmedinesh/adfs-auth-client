//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2018.03.20 at 12:43:08 PM IST 
//

package com.itzmeds.adfs.client.response.saml;

import java.util.Arrays;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * Java class for anonymous complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within
 * this class
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = { "x509Certificate" })
@XmlRootElement(name = "X509Data")
public class X509Data {

	@XmlElement(name = "X509Certificate", namespace = "http://www.w3.org/2000/09/xmldsig#", required = true)
	protected byte[] x509Certificate;

	/**
	 * Gets the value of the x509Certificate property.
	 * 
	 * @return possible object is byte[]
	 */
	public byte[] getX509Certificate() {
		return x509Certificate;
	}

	/**
	 * Sets the value of the x509Certificate property.
	 * 
	 * @param value
	 *            allowed object is byte[]
	 */
	public void setX509Certificate(byte[] value) {
		this.x509Certificate = value;
	}

	@Override
	public String toString() {
		return "X509Data [x509Certificate=" + Arrays.toString(x509Certificate) + "]";
	}

}
