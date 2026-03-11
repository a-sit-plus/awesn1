// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Encodable

/**
 * Structural ASN.1 signature value.
 *
 * Implementations are intentionally open to allow algorithm-specific extensions.
 */
interface SignatureValue<out A: Asn1Element>: Asn1Encodable<A> {}
typealias GenericSignatureValue = SignatureValue<Asn1Element>