// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

package at.asitplus.awesn1.serialization

import at.asitplus.awesn1.Identifiable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule

@OptIn(ExperimentalStdlibApi::class)
val SerializationOidSetAmbiguityRejection by matrixSuite {
    // A(oid=1.2.3.4, payload={1.2.3.7}) and B(oid=1.2.3.7, payload={1.2.3.4})
    // would both encode as 310a06032a030406032a0307 if SET subtypes were allowed.
    "SET subtype registration is rejected even with overridden leading tags" {
        for (tags in listOf(emptyArray(), arrayOf(Asn1Element.Tag.SEQUENCE))) {
            shouldThrow<IllegalArgumentException> {
                asn1OpenPolymorphicByOidSerializer<OidSetValue>("OidSetValue") {
                    subtype<OidSetA>(OidSetA, *tags)
                }
            }.message shouldContain "SET"
        }
    }

    "SET catch-all registration is rejected" {
        shouldThrow<IllegalArgumentException> {
            asn1OpenPolymorphicByOidSerializer<OidSetValue>("OidSetValue") {
                catchAll<OidSetA>(Asn1Element.Tag.SEQUENCE)
            }
        }.message shouldContain "SET"
    }

    "SET input is rejected even with a custom OID selector" {
        for (customSelector in listOf(false, true)) {
            val serializer = if (customSelector) {
                asn1OpenPolymorphicByOidSerializer<OidSetValue>("OidSetValue", oidSelector = { OidSetB.oid }) {
                    subtype<OidSetB>(OidSetB)
                }
            } else asn1OpenPolymorphicByOidSerializer<OidSetValue>("OidSetValue") {
                subtype<OidSetB>(OidSetB)
            }
            shouldThrow<SerializationException> {
                DER.decodeFromByteArray(serializer, "310a06032a030406032a0307".hexToByteArray())
            }.message shouldContain "SET"
        }
    }

    "SEQUENCE subtypes may still contain SET payloads" {
        val der = DER {
            serializersModule = SerializersModule {
                polymorphicByOid(OidSetValue::class, serialName = "OidSetValue") {
                    subtype<OidSetB>(OidSetB)
                }
            }
        }
        val value: OidSetValue = OidSetB(setOf(OidSetA.oid, OidSetB.oid))
        der.decodeFromByteArray<OidSetValue>(der.encodeToByteArray(value)) shouldBe value
    }
}

private interface OidSetValue : Identifiable

@Serializable(with = OidSetA.Serializer::class)
private data class OidSetA(val values: Set<ObjectIdentifier>) : OidSetValue, Identifiable by Companion {
    object Serializer : KSerializer<OidSetA> {
        //this delegation is the culprit
        private val delegate = SetSerializer(ObjectIdentifier.serializer())
        override val descriptor = delegate.descriptor
        override fun serialize(encoder: Encoder, value: OidSetA) = delegate.serialize(encoder, value.values)
        override fun deserialize(decoder: Decoder) = OidSetA(delegate.deserialize(decoder))
    }

    companion object : OidProvider<OidSetA> {
        override val oid = ObjectIdentifier("1.2.3.4")
    }
}

@Serializable
private data class OidSetB(val values: Set<ObjectIdentifier>) : OidSetValue, Identifiable by Companion {
    companion object : OidProvider<OidSetB> {
        override val oid = ObjectIdentifier("1.2.3.7")
    }
}
