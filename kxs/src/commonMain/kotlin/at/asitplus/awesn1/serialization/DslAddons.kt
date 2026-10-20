// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.encoding

import at.asitplus.awesn1.serialization.Der
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.serializer

/**
 * Encodes [value] with [serializer] and the contextual [der], then appends the resulting TLV element.
 *
 * If the configured DER encoding omits [value], such as a nullable `null` when explicit nulls are disabled,
 * nothing is appended.
 *
 * @throws SerializationException if serialization constraints are violated
 */
@Throws(Throwable::class)
context(der: Der)
fun <Serializable> Asn1TreeBuilder.append(serializer: KSerializer<Serializable>, value: Serializable) {
    der.encodeToTlv(serializer, value)?.let { +it }
}

/**
 * Encodes [value] with its inferred serializer and the contextual [der], then appends the resulting TLV element.
 *
 * The serializer is inferred from the static type [T], which must have an available kotlinx serializer.
 *
 * @throws SerializationException if serialization constraints are violated
 */
@OptIn(ExperimentalSerializationApi::class)
@Throws(Throwable::class)
context(der: Der)
inline fun <reified Serializable> Asn1TreeBuilder.append(value: Serializable) =
    append(serializer(), value)
