// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalObjCName::class)

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1BitString
import kotlin.experimental.ExperimentalObjCName

/**
 * @see X509TbsCertificate.issuerUniqueID
 */
@Throws(IllegalArgumentException::class)
@ObjCName("issuerUniqueID")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_X509TbsCertificate_issuerUniqueID(it: X509TbsCertificate) = it.issuerUniqueID

/**
 * @see X509TbsCertificate.subjectUniqueID
 */
@Throws(IllegalArgumentException::class)
@ObjCName("subjectUniqueID")
@Deprecated(
    message = "Objective-C export only",
    level = DeprecationLevel.HIDDEN
)
fun __apple_workaround_X509TbsCertificate_subjectUniqueID(it: X509TbsCertificate) = it.subjectUniqueID
