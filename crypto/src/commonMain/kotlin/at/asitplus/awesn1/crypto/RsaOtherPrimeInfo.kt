// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import kotlinx.serialization.Serializable

@Serializable
data class RsaOtherPrimeInfo(
    val prime: Asn1Integer,
    val exponent: Asn1Integer,
    val coefficient: Asn1Integer,
)
