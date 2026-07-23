package at.asitplus.awesn1.crypto

import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

/**
 * The `iPAddress` GeneralName (RFC 5280 `GeneralName` CHOICE `[7]`, an OCTET STRING) is the *same* type reused
 * across two contexts, each with its own octet-count rule:
 *
 *  - subjectAltName / issuerAltName ([RFC 5280 §4.2.1.6](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6)):
 *    a bare address — **4** octets (IPv4) or **16** octets (IPv6).
 *  - nameConstraints ([RFC 5280 §4.2.1.10](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10)):
 *    address **followed by subnet mask** — **8** octets (IPv4) or **32** octets (IPv6).
 *
 * [X509GeneralName.IpAddress] models that single, context-free type, so its length check must accept the union
 * `{4, 8, 16, 32}` and reject everything else. (Enforcing the exact per-context set would require knowing whether
 * the name sits in a SAN or a name constraint, which this type intentionally does not.)
 */
val IpAddressGeneralNameLengthTest by matrixSuite {

    "legal" - {
        listOf(4, 8, 16, 32).asData(nameFn = { "iPAddress accepts $it octets and round-trips the value" }) test { size ->
            val octets = ByteArray(size) { it.toByte() }
            // must not throw at construction, and the strict getter must not throw either
            X509GeneralName.IpAddress(octets).value shouldBe octets
        }
    }

    "illegal" - {
        listOf(0, 1, 3, 5, 7, 15, 17, 31, 33, 64).asData(nameFn = { "iPAddress rejects $it octets" }) test { size ->
            shouldThrow<Asn1StructuralException> {
                X509GeneralName.IpAddress(ByteArray(size))
            }
        }
    }
}
