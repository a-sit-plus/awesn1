// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto.pki

import at.asitplus.awesn1.Asn1BitString

/**
 * @see X509TbsCertificate.issuerUniqueID
 */
@Throws(IllegalArgumentException::class)
fun X509TbsCertificate.issuerUniqueID(): Asn1BitString? = issuerUniqueID

/**
 * @see X509TbsCertificate.subjectUniqueID
 */
@Throws(IllegalArgumentException::class)
fun X509TbsCertificate.subjectUniqueID(): Asn1BitString? = subjectUniqueID
