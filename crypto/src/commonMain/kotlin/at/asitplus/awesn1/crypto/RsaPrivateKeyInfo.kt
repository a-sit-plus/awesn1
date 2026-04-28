// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import kotlinx.serialization.Serializable

@Serializable
data class RsaPrivateKeyInfo(
    val version: Int,
    val modulus: Asn1Integer,
    val publicExponent: Asn1Integer,
    val privateExponent: Asn1Integer,
    val prime1: Asn1Integer,
    val prime2: Asn1Integer,
    val exponent1: Asn1Integer,
    val exponent2: Asn1Integer,
    val coefficient: Asn1Integer,
    val otherPrimeInfos: List<RsaOtherPrimeInfo>? = null,
)
