// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization.internal

import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor

private val setDescriptor: SerialDescriptor = SetSerializer(String.serializer()).descriptor

internal val SerialDescriptor.isSetDescriptor: Boolean
    get() = setDescriptor::class.isInstance(this)
