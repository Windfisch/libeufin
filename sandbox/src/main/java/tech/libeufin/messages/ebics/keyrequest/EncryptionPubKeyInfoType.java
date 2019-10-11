//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.10.10 at 06:36:01 PM CEST 
//


package tech.libeufin.messages.ebics.keyrequest;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * Datentyp für öffentliche Verschlüsselungsschlüssel.
 * 
 * <p>Java class for EncryptionPubKeyInfoType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="EncryptionPubKeyInfoType">
 *   &lt;complexContent>
 *     &lt;extension base="{urn:org:ebics:H004}PubKeyInfoType">
 *       &lt;sequence>
 *         &lt;element name="EncryptionVersion" type="{urn:org:ebics:H004}EncryptionVersionType"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EncryptionPubKeyInfoType", propOrder = {
    "encryptionVersion"
})
public class EncryptionPubKeyInfoType
    extends PubKeyInfoTypeAtEbicsTypes
{

    @XmlElement(name = "EncryptionVersion", required = true)
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlSchemaType(name = "token")
    protected String encryptionVersion;

    /**
     * Gets the value of the encryptionVersion property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getEncryptionVersion() {
        return encryptionVersion;
    }

    /**
     * Sets the value of the encryptionVersion property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setEncryptionVersion(String value) {
        this.encryptionVersion = value;
    }

}