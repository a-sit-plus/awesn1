package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1StructuralException

/**
 * @see X509GeneralName.Rfc822.value
 */
@Throws(Asn1Exception::class)
fun X509GeneralName.Rfc822.value(): String = value

/**
 * @see X509GeneralName.Dns.value
 */
@Throws(Asn1Exception::class)
fun X509GeneralName.Dns.value(): String = value

/**
 * @see X509GeneralName.UniformResourceIdentifier.value
 */
@Throws(Asn1Exception::class)
fun X509GeneralName.UniformResourceIdentifier.value(): String = value

/**
 * @see X509GeneralName.IpAddress.value
 */
@Throws(Asn1StructuralException::class)
fun X509GeneralName.IpAddress.value(): ByteArray = value