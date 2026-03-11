// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.serialization.InternalDefaultDerSerializersModuleRegistry

const val DEFAULT_DER_SIGNATURE_VALUE_SERIAL_NAME =
    "at.asitplus.awesn1.crypto.SignatureValue"

private var signatureValueDefaultDerRegistered = false

@OptIn(InternalAwesn1Api::class)
fun registerSignatureValueForDefaultDer() {
    if (signatureValueDefaultDerRegistered) return
    InternalDefaultDerSerializersModuleRegistry.registerTagOpenPolymorphism(
        baseClass = SignatureValue::class,
        serialName = DEFAULT_DER_SIGNATURE_VALUE_SERIAL_NAME,
    ) {
        subtype<BitStringSignatureValue>(Asn1Element.Tag.BIT_STRING)
        subtype<EcdsaSignatureValue>(Asn1Element.Tag.SEQUENCE)
    }
    signatureValueDefaultDerRegistered = true
}
