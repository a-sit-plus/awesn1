// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(kotlinx.serialization.SealedSerializationApi::class)

package at.asitplus.awesn1.serialization.internal

import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor

private val setDescriptor: SerialDescriptor = SetSerializer(String.serializer()).descriptor

private interface Asn1SetSerialDescriptor {
    val sortChildren: Boolean
}

private class NamedAsn1SetSerialDescriptor(
    private val name: String,
    private val delegate: SerialDescriptor,
    override val sortChildren: Boolean,
) : SerialDescriptor by delegate, Asn1SetSerialDescriptor {
    override val serialName: String get() = name
}

internal val SerialDescriptor.isSetDescriptor: Boolean
    get() = this is Asn1SetSerialDescriptor || setDescriptor::class.isInstance(this)

internal val SerialDescriptor.isKotlinSetDescriptor: Boolean
    get() = setDescriptor::class.isInstance(this)

internal val SerialDescriptor.sortSetChildren: Boolean
    get() = (this as? Asn1SetSerialDescriptor)?.sortChildren ?: true

internal fun SerialDescriptor.asNamedSetDescriptor(serialName: String, sortChildren: Boolean = true): SerialDescriptor =
    NamedAsn1SetSerialDescriptor(serialName, this, sortChildren)
