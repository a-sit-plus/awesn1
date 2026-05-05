// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization

import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor

/**
 * Explicit-tag modelling wrapper.
 *
 * This wrapper requires an effective implicit tag override resolving to
 * CONTEXT-SPECIFIC + CONSTRUCTED. Missing/invalid configuration is rejected
 * at runtime by the DER serializer/decoder.
 */
@Serializable
data class ExplicitlyTagged<T>(
    val value: T,
) {
    operator fun getValue(thisRef: Any?, property: Any?): T = value
}

operator fun <T> ExplicitlyTagged<T>?.getValue(thisRef: Any?, property: Any?): T? = this?.value

/**
 * OCTET STRING encapsulation wrapper.
 *
 * This is encoded as UNIVERSAL OCTET STRING with primitive form and the
 * encoded payload value bytes as content.
 */
@Serializable
@Asn1Tag(
    tagNumber = 4u,
    tagClass = Asn1Tag.Class.UNIVERSAL,
    constructed = Asn1Tag.ConstructedBit.PRIMITIVE,
)
data class OctetStringEncapsulated<T>(
    val value: T,
)

private const val ExplicitlyTaggedSerialName =
    "at.asitplus.awesn1.serialization.ExplicitlyTagged"

internal fun SerialDescriptor.isAsn1ExplicitWrapperDescriptor(): Boolean =
    serialName.removeSuffix("?").substringBefore('<').let { rawName -> rawName == ExplicitlyTaggedSerialName }
