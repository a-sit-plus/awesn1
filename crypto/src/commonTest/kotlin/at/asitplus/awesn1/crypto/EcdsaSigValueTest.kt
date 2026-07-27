package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.crypto.EcdsaSigValue.Companion.toEcdsaSigValue
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlin.io.encoding.Base64

val EcdsaSigValueTest by matrixSuite {
    "Test" {
        val sigValue = Base64.UrlSafe.decode("A0kAMEYCIQCnXiAKLwJP0uXBKtTmJccBu" +
            "yddhFFVTz-J0DNHBi21lgIhAI1SUoIYXXqdZMrKox4_HBTEmuxvG9sloAoDH5rfsyd4")
            .let { DER.decodeFromDer<X509SignatureValue>(it) }
        sigValue.toEcdsaSigValue().let {
            it.r.toString() shouldBe "75702550467927847687504835259358957068594330833158195591194084637648375100822"
            it.s.toString() shouldBe "63921562560111841846899158949481573510824775155107323853077162713843342976888"
        }
    }
}
