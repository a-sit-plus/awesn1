// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.encoding.internal

import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.InternalAwesn1Api
import at.asitplus.awesn1.throughBuffer

@InternalAwesn1Api
@Throws(Asn1Exception::class)
fun Asn1Encodable<*>.encodeToDer(sink: Sink) {
    encodeToTlv().encodeTo(sink)
}
