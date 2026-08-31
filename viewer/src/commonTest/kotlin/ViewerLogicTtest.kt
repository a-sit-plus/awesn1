package at.asitplus.awesn1.viewer

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.describeAll
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow

val alibi by matrixSuite {
    "decodes hex, base64, PEM, and auto formats" {
        val der = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)
        decodeInput("30 03:02 01 01", InputFormat.HEX).bytes.toList() shouldBe der.toList()
        decodeInput("MAMCAQE=", InputFormat.BASE64).bytes.toList() shouldBe der.toList()
        decodeInput("BAP7__8", InputFormat.AUTO).bytes.toList() shouldBe
                byteArrayOf(0x04, 0x03, 0xfb.toByte(), 0xff.toByte(), 0xff.toByte()).toList()
        val pem = decodeInput("-----BEGIN TEST-----\n\nMAMCAQE=\n-----END TEST-----", InputFormat.PEM)
        pem.bytes.toList() shouldBe der.toList()
        pem.pemLabel shouldBe "TEST"
        pem.element.prettyPrint().contains("Sequence") shouldBe true
        val pemChain = decodeInput(
            "-----BEGIN TEST-----\nMAMCAQE=\n-----END TEST-----\n" +
                    "-----BEGIN TEST-----\nMAMCAQI=\n-----END TEST-----",
            InputFormat.PEM,
        )
        pemChain.elements.size shouldBe 2
        decodeInput("MAMCAQE=", InputFormat.AUTO).bytes.toList() shouldBe der.toList()
    }

    "rejects malformed input" {
        shouldThrow<IllegalArgumentException> { decodeInput("abc", InputFormat.HEX) }
        shouldThrow<IllegalArgumentException> { decodeInput("-----BEGIN A-----\nMAMCAQE=\n-----END B-----", InputFormat.PEM) }
    }

    "loads OID descriptions and colors exact DER bytes" {
        KnownOIDs.describeAll()
        registerViewerOids()
        KnownOIDs[ObjectIdentifier("2.5.4.3")]?.isNotBlank() shouldBe true
        KnownOIDs[ANDROID_KEY_ATTESTATION_OID] shouldBe "androidKeyAttestation (Android key attestation extension)"
        val decoded = decodeInput("30 03 02 01 01", InputFormat.HEX)
        coloredHex(decoded.element).first.map { it.value }.toByteArray().toList() shouldBe decoded.bytes.toList()
        coloredHex(decoded.element).first.map { it.path } shouldBe
                listOf(listOf(0), listOf(0), listOf(0, 0), listOf(0, 0), listOf(0, 0))
        genericAsn1Lines(decoded.element).mapNotNull { it.path } shouldBe listOf(listOf(0), listOf(0, 0))
        genericAsn1Lines(decoded.element)[1].text shouldBe "1  tag=2 (=0x02) (INTEGER), length=1 (0x01)"

        val encapsulated = decodeInput("04 03 02 01 01", InputFormat.HEX).element
        genericAsn1Lines(encapsulated).mapNotNull { it.path } shouldBe listOf(listOf(0), listOf(0, 0))
        genericAsn1Lines(encapsulated).first().text.startsWith("(3 bytes, 1 elem)") shouldBe true
        coloredHex(encapsulated).first.map { it.path } shouldBe
                listOf(listOf(0), listOf(0), listOf(0, 0), listOf(0, 0), listOf(0, 0))

        val concatenated = decodeInput("30 03 02 01 01 30 03 02 01 02", InputFormat.HEX)
        val lines = genericAsn1Lines(concatenated.elements)
        lines.filter { it.isRoot }.map { it.memberName } shouldBe listOf("(1/2)", "(2/2)")
        lines.filter { it.isRoot }.map { it.byteOffset } shouldBe listOf(0, 5)
        coloredHex(concatenated.elements).first.drop(5).first().path shouldBe listOf(1)
    }

    "renders Android key attestation schema hints" {
        val decoded = decodeInput(
            "30 33 02 01 64 0A 01 00 02 01 64 0A 01 02 04 01 AA 04 00 " +
                    "30 0C A1 05 31 03 02 01 02 A2 03 02 01 01 " +
                    "30 12 BF 85 40 0E 30 0C 04 01 AA 01 01 FF 0A 01 01 04 01 BB",
            InputFormat.HEX,
        )
        val names = androidKeyAttestationSchemaNames(decoded.element)
        names[listOf(0)] shouldBe "KeyDescription"
        names[listOf(0, 2)] shouldBe "keyMintVersion"
        names[listOf(0, 3)] shouldBe "keyMintSecurityLevel"
        names[listOf(0, 6, 0)] shouldBe "purpose"
        names[listOf(0, 6, 1)] shouldBe "algorithm"
        names[listOf(0, 7, 0)] shouldBe "rootOfTrust"
        names[listOf(0, 7, 0, 0)] shouldBe "RootOfTrust"
        names[listOf(0, 7, 0, 0, 2)] shouldBe "verifiedBootState"
        val values = schemaValueNames(decoded.element, names)
        values[listOf(0, 1)] shouldBe "Software"
        values[listOf(0, 3)] shouldBe "StrongBox"
        values[listOf(0, 7, 0, 0, 2)] shouldBe "SelfSigned"
        genericAsn1Lines(decoded.element, names, values).single { it.path == listOf(0, 3) }.text shouldBe
                "StrongBox  tag=10 (=0x0A) (ENUMERATED), length=1 (0x01)"
    }

    "names every Android key attestation enumeration, version and identifier" {
        val decoded = decodeInput(
            "308201070202012C0A01010202012C0A010204096368616C6C656E676504003050BF853D080206016507623000BF8545" +
                    "40043E303C31163014040F636F6D2E6578616D706C652E61707002012A31220420000102030405060708090A0B0C0D0E" +
                    "0F101112131415161718191A1B1C1D1E1F308197A1083106020102020103A203020103A30402020100A5053103020104" +
                    "A6053103020105AA03020101AB03020102BF837803020103BF853E03020100BF854030302E0420000000000000000000" +
                    "00000000000000000000000000000000000000000000000101FF0A0100040400000000BF85410502030222E0BF854205" +
                    "02030316A8BF8546080406676F6F676C65BF854E0602040134D9A5",
            InputFormat.HEX,
        )
        val names = androidKeyAttestationSchemaNames(decoded.element)
        val values = schemaValueNames(decoded.element, names)
        values[listOf(0, 0)] shouldBe "KeyMint 3.0"
        values[listOf(0, 1)] shouldBe "TrustedEnvironment"
        values[listOf(0, 2)] shouldBe "KeyMint 3.0"
        values[listOf(0, 3)] shouldBe "StrongBox"
        values[listOf(0, 4)] shouldBe "\"challenge\""

        // softwareEnforced: creationDateTime and the DER blob nested in attestationApplicationId
        values[listOf(0, 6, 0, 0)] shouldBe "2018-08-05T00:00:00Z"
        names[listOf(0, 6, 1)] shouldBe "attestationApplicationId"
        names[listOf(0, 6, 1, 0, 0)] shouldBe "AttestationApplicationId"
        names[listOf(0, 6, 1, 0, 0, 0, 0)] shouldBe "AttestationPackageInfo"
        names[listOf(0, 6, 1, 0, 0, 0, 0, 0)] shouldBe "package_name"
        names[listOf(0, 6, 1, 0, 0, 1, 0)] shouldBe "signature_digest"
        values[listOf(0, 6, 1, 0, 0, 0, 0, 0)] shouldBe "\"com.example.app\""

        // hardwareEnforced: every enumerated, packed and identifier value
        values[listOf(0, 7, 0, 0, 0)] shouldBe "Sign"
        values[listOf(0, 7, 0, 0, 1)] shouldBe "Verify"
        values[listOf(0, 7, 1, 0)] shouldBe "EC"
        values[listOf(0, 7, 2, 0)] shouldBe null
        values[listOf(0, 7, 3, 0, 0)] shouldBe "SHA-256"
        values[listOf(0, 7, 4, 0, 0)] shouldBe "RSA-PKCS1-1.5-Sign"
        values[listOf(0, 7, 5, 0)] shouldBe "P-256"
        values[listOf(0, 7, 6, 0)] shouldBe "ML-DSA-87"
        values[listOf(0, 7, 7, 0)] shouldBe "Password | Fingerprint"
        values[listOf(0, 7, 8, 0)] shouldBe "Generated"
        values[listOf(0, 7, 9, 0, 2)] shouldBe "Verified"
        values[listOf(0, 7, 10, 0)] shouldBe "14.0.0"
        values[listOf(0, 7, 11, 0)] shouldBe "2024-08"
        values[listOf(0, 7, 12, 0)] shouldBe "\"google\""
        values[listOf(0, 7, 13, 0)] shouldBe "2024-08-05"
        genericAsn1Lines(decoded.element, names, values).single { it.path == listOf(0, 7, 5, 0) }.text shouldBe
                "P-256  tag=2 (=0x02) (INTEGER), length=1 (0x01)"
    }

    "falls back to the generic tree when semantic enrichment does not apply" {
        // softwareEnforced is an INTEGER instead of an AuthorizationList, RootOfTrust is truncated to two members,
        // and the enumerations, packed versions and patch levels all carry out-of-range values.
        val decoded = decodeInput(
            "304F0201640A01090201640A010104017804000201053039A1053103020163BF837807020500FFFFFFFFBF853E030201" +
                    "4DBF85400B30090404000000000101FFBF85410602040098967FBF854203020101",
            InputFormat.HEX,
        )
        val names = androidKeyAttestationSchemaNames(decoded.element)
        val values = schemaValueNames(decoded.element, names)

        // Structural hints that still apply are kept ...
        names[listOf(0)] shouldBe "KeyDescription"
        names[listOf(0, 6)] shouldBe "softwareEnforced"
        names[listOf(0, 7, 3)] shouldBe "rootOfTrust"
        names[listOf(0, 7, 3, 0)] shouldBe "RootOfTrust"
        values[listOf(0, 3)] shouldBe "TrustedEnvironment"
        values[listOf(0, 7, 1, 0)] shouldBe "Any"
        // ... while everything unrecognized simply carries no hint, leaving the generic rendering in place.
        names[listOf(0, 7, 3, 0, 2)] shouldBe null // verifiedBootState: absent from the truncated RootOfTrust
        values[listOf(0, 1)] shouldBe null // SecurityLevel 9
        values[listOf(0, 7, 0, 0, 0)] shouldBe null // KeyPurpose 99
        values[listOf(0, 7, 2, 0)] shouldBe null // KeyOrigin 77
        values[listOf(0, 7, 4, 0)] shouldBe null // osVersion 9999999, too wide to be MMmmss
        values[listOf(0, 7, 5, 0)] shouldBe null // osPatchLevel 1, neither YYYYMM nor YYYYMMDD
        genericAsn1Lines(decoded.element, names, values).single { it.path == listOf(0, 7, 0, 0, 0) }.text shouldBe
                "99  tag=2 (=0x02) (INTEGER), length=1 (0x01)"
    }

    "renders every node of any valid ASN.1, however unlike a known schema" {
        listOf(
            "3000", // empty SEQUENCE
            "0500", // bare NULL
            "30293027302530233021301F301D301B30193017301530133011300F300D300B3009300730053003020101", // deeply nested
            "300602010102010A", // certificate-shaped but not a certificate
            "304F0201640A01090201640A010104017804000201053039A1053103020163BF837807020500FFFFFFFFBF853E030201" +
                    "4DBF85400B30090404000000000101FFBF85410602040098967FBF854203020101",
        ).forEach { hex ->
            val decoded = decodeInput(hex, InputFormat.HEX)
            // Enrichment is decoration: it must never throw, whatever the input looks like.
            val names = schemaMemberNames(decoded.bytes, decoded.element)
            val values = schemaValueNames(decoded.element, names)
            val lines = genericAsn1Lines(decoded.element, names, values)
            val (bytes, truncated) = coloredHex(decoded.element)
            truncated shouldBe false
            // Every node of the tree is rendered, and the hex pane still reproduces the input exactly.
            lines.mapNotNull { it.path }.toSet() shouldBe bytes.map { it.path }.toSet()
            bytes.map { it.value }.toByteArray().toList() shouldBe decoded.bytes.toList()
        }
    }

    "maps nested CSR elements to their exact DER range" {
        val csr = decodeInput(
            "MIHQMIGDAgEAMA8xDTALBgNVBAMMBHRlc3QwKjAFBgMrZXADIQD7Fua9ZF+wPXVd" +
                    "DCBwQr+Aqny6OFvs25wZ/P4LyVsYmKBBMD8GCSqGSIb3DQEJDjEyMDAwLgYDVR0R" +
                    "BCcwJaAjBgorBgEEAYI3FAIDoBUME2FkZHJlc3NAZG9tYWluLnRlc3QwBQYDK2Vw" +
                    "A0EAUp5FenHF1rZzRGU+7wiF+/D1bfyDRF0dzWz2sl44nltu8iLjHO3aIfOTYWpq" +
                    "ZlaDg1Bq3L7Fcb7If4yZAsE5Cw==",
            InputFormat.BASE64,
        )
        val tagged = genericAsn1Lines(csr.element).single {
            it.text.contains("CONTEXT_SPECIFIC 0") && it.byteLength == 23
        }
        tagged.byteOffset shouldBe 114
        coloredHex(csr.element).first[114].path shouldBe tagged.path
        coloredHex(csr.element).first.slice(114..136).all {
            it.path.take(tagged.path!!.size) == tagged.path
        } shouldBe true
        val names = schemaMemberNames(csr.bytes, csr.element)
        names[listOf(0, 0)] shouldBe "certificationRequestInfo"
        names[listOf(0, 0, 2)] shouldBe "subjectPKInfo"
        names[listOf(0, 1)] shouldBe "signatureAlgorithm"
        names[listOf(0, 2)] shouldBe "signature"
        genericAsn1Lines(csr.element, names).single { it.path == listOf(0, 0, 2) }.memberName shouldBe "subjectPKInfo"
    }

    "names every supported crypto structure" {
        mapOf(
            "30 06 02 01 03 02 01 03" to "RSAPublicKey",
            "30 06 02 01 01 04 01 01" to "ECPrivateKey",
            "30 1B 02 01 00 02 01 01 02 01 01 02 01 01 02 01 01 02 01 01 02 01 01 02 01 01 02 01 01" to "RSAPrivateKey",
            "30 0C 30 05 06 03 2B 65 70 03 03 00 01 02" to "SubjectPublicKeyInfo",
            "30 0A 30 05 06 03 2B 65 70 04 01 00" to "EncryptedPrivateKeyInfo",
            "30 0E 02 01 00 30 05 06 03 2B 65 70 04 02 04 00" to "PrivateKeyInfo",
        ).forEach { (hex, rootName) ->
            val decoded = decodeInput(hex, InputFormat.HEX)
            schemaMemberNames(decoded.bytes, decoded.element)[listOf(0)] shouldBe rootName
        }
    }
}
