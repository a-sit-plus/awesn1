@file:OptIn(ExperimentalObjCName::class)
// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1StructuralException
import kotlin.experimental.ExperimentalObjCName

/**
 * @see X509GeneralName.Rfc822.value
 */
@Throws(Asn1Exception::class)
@ObjCName("value")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_X509GeneralName_Rfc822_value(it: X509GeneralName.Rfc822) = it.value

/**
 * @see X509GeneralName.Dns.value
 */
@Throws(Asn1Exception::class)
@ObjCName("value")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_X509GeneralName_Dns_value(it: X509GeneralName.Dns) = it.value

/**
 * @see X509GeneralName.UniformResourceIdentifier.value
 */
@Throws(Asn1Exception::class)
@ObjCName("value")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_X509GeneralName_URI_value(it: X509GeneralName.UniformResourceIdentifier) = it.value

/**
 * @see X509GeneralName.IpAddress.value
 */
@Throws(Asn1StructuralException::class)
@ObjCName("value")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_X509GeneralName_IpAddress_value(it: X509GeneralName.IpAddress) = it.value
