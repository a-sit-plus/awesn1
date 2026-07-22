// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalObjCName::class)

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.ObjectIdentifier
import kotlin.experimental.ExperimentalObjCName

/**
 * @see X509AlgorithmIdentifier.parameters
 */
@Throws(Asn1Exception::class)
@ObjCName("parameters")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_X509AlgorithmIdentifier_parameters(it: X509AlgorithmIdentifier) = it.parameters

/**
 * @see X509AlgorithmIdentifier.rsaSsaPssParams
 */
@Throws(Asn1Exception::class)
@ObjCName("rsaSsaPssParams")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_X509AlgorithmIdentifier_rsaSsaPssParams(it: X509AlgorithmIdentifier) = it.rsaSsaPssParams
