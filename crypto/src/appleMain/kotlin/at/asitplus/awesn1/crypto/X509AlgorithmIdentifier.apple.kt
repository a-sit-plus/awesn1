// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier

/**
 * @see X509AlgorithmIdentifier.parameters
 */
@Throws(Asn1Exception::class)
fun X509AlgorithmIdentifier.parameters(): Asn1Element? = parameters

/**
 * @see X509AlgorithmIdentifier.rsaSsaPssParams
 */
@Throws(Asn1Exception::class)
fun X509AlgorithmIdentifier.rsaSsaPssParams(): RsaSsaPssParams? = rsaSsaPssParams
