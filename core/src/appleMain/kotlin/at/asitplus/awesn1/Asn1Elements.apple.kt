// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1

/** Obj-C/Swift workaround for KT-63047.
 * @see Asn1EncapsulatingOctetString.element */
@Throws(Asn1Exception::class)
fun Asn1EncapsulatingOctetString.element() = element
