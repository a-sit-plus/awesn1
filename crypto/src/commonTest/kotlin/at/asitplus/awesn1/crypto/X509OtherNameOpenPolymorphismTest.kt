// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.crypto.pki.X509GeneralNames
import at.asitplus.awesn1.serialization.Asn1Tag
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.ExplicitlyTagged
import at.asitplus.awesn1.serialization.OidProvider
import at.asitplus.awesn1.serialization.polymorphicByOid
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.SerializersModule

val X509OtherNameOpenPolymorphismTest by matrixSuite {
    val der = DER {
        serializersModule = SerializersModule {
            polymorphicByOid(
                X509GeneralName.OtherName::class,
                serialName = "X509OtherName",
            ) {
                subtype<UserPrincipalName>(UserPrincipalName)
                catchAll<X509GeneralName.GenericOther>()
            }
        }
    }

    "custom DER resolves registered otherName semantics by OID" {
        val names = X509GeneralNames(listOf(X509GeneralName.Other(UserPrincipalName("alice@example.com"))))

        val decoded = der.decodeFromByteArray<X509GeneralNames>(der.encodeToByteArray(names))
        val otherName = decoded.entries.single().shouldBeInstanceOf<X509GeneralName.Other>()
            .value.shouldBeInstanceOf<UserPrincipalName>()

        otherName.oid shouldBe UserPrincipalName.oid
        otherName.value shouldBe "alice@example.com"
    }

    "custom DER preserves unknown otherName OIDs through the generic fallback" {
        val unknownOid = ObjectIdentifier("1.2.3.4.5")
        val raw = X509GeneralName.GenericOther(unknownOid, Asn1String.UTF8("opaque").encodeToTlv())
        val names = X509GeneralNames(listOf(X509GeneralName.Other(raw)))

        val encoded = der.encodeToByteArray(names)
        val decoded = der.decodeFromByteArray<X509GeneralNames>(encoded)
        val fallback = decoded.entries.single().shouldBeInstanceOf<X509GeneralName.Other>()
            .value.shouldBeInstanceOf<X509GeneralName.GenericOther>()

        fallback.oid shouldBe unknownOid
        der.encodeToByteArray(decoded) shouldBe encoded
    }
}

@Serializable
data class UserPrincipalName(
    @Asn1Tag(tagNumber = 0u, constructed = Asn1Tag.ConstructedBit.CONSTRUCTED)
    private val taggedValue: ExplicitlyTagged<Asn1String.UTF8>,
) : X509GeneralName.OtherName {

    constructor(value: String) : this(ExplicitlyTagged(Asn1String.UTF8(value)))

    override val oid: ObjectIdentifier get() = Companion.oid
    val value: String get() = taggedValue.value.value

    companion object : OidProvider<UserPrincipalName> {
        override val oid: ObjectIdentifier = ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
    }
}
