@file:OptIn(ExperimentalObjCName::class)
// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

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
fun __apple_workaround_X509AlgorithmIdentifier_parameters(it: X509AlgorithmIdentifier) = it.parameters

/**
 * @see X509AlgorithmIdentifier.rsaSsaPssParams
 */
@Throws(Asn1Exception::class)
@ObjCName("rsaSsaPssParams")
fun __apple_workaround_X509AlgorithmIdentifier_rsaSsaPssParams(it: X509AlgorithmIdentifier) = it.rsaSsaPssParams
