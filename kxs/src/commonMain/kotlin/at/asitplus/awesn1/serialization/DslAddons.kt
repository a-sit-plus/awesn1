package at.asitplus.awesn1.encoding

import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.serialization.Der
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer



/**
 * appends a single ASN1-Serializable to this ASN.1 structure
 * @throws Asn1Exception in case encoding constraints of children are violated
 */
@Throws(Throwable::class)
fun <Serializable> Asn1TreeBuilder.append(serializer: KSerializer<Serializable>, value: Serializable, der:Der) {
    der.encodeToTlv(serializer, value)?.let { +it }
}

@OptIn(ExperimentalSerializationApi::class)
@Throws(Throwable::class)
inline fun <reified Serializable> Asn1TreeBuilder.append(value: Serializable, der: Der) =
    append(serializer(), value, der)



/**
 * appends a single [Asn1Encodable] to this ASN.1 structure
 * @throws Asn1Exception in case encoding constraints of children are violated
 */

@OptIn(ExperimentalSerializationApi::class)
context(der:Der,  treeBuilder: Asn1TreeBuilder)
@Throws(Throwable::class)
inline operator fun <reified Serializable> Serializable.unaryPlus() {
    treeBuilder.append(this, der)
}
