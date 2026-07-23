package at.asitplus.awesn1

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

/*
 * Regression ("A/B") coverage for two fixed [Asn1String] validators:
 *
 *  1. IA5 — the alphabet is ITU-T T.50 / ISO 646, the full 7-bit range 0x00–0x7F **including DELETE (0x7F)**.
 *     Before the fix the upper bound was 0x7E, so DELETE was wrongly rejected.
 *  3. UTF8 — [Asn1String.UTF8.isValid] must report UTF-8 *well-formedness*, not "contains U+FFFD". Before the fix,
 *     a value that legitimately contains U+FFFD was wrongly rejected, and malformed bytes were only caught by
 *     accident via the decode-replacement marker.
 *
 * Each case is a pair: the input that behaves *differently* after the fix (A), plus a neighbouring input that must
 * keep its old behaviour (B), so the boundary is pinned from both sides.
 */
val Asn1StringValidatorFixTest by matrixSuite {

    val DEL = 0x7f.toChar()             // U+007F DELETE — legal IA5, was rejected before the fix
    val TILDE = 0x7e.toChar()           // U+007E '~'     — top of the old range, still legal
    val PAD = 0x80.toChar()             // U+0080         — first code point outside IA5
    val REPLACEMENT = 0xfffd.toChar()   // U+FFFD REPLACEMENT CHARACTER — a legitimate UTF-8 character

    // ---- Fix 1: IA5 ----

    "IA5 (A) accepts DELETE 0x7f — via both the String and the raw-bytes path" {
        shouldNotThrowAny { Asn1String.IA5(DEL.toString()) }
        Asn1String.IA5(DEL.toString()).isValid shouldBe true
        Asn1String.IA5(byteArrayOf(0x7f)).isValid shouldBe true      // raw byte 0x7f
    }

    "IA5 (B) still accepts 0x7e and still rejects the first out-of-range code point 0x80" {
        Asn1String.IA5(byteArrayOf(0x7e)).isValid shouldBe true
        // 0x80 as a well-formed UTF-8 char (C2 80) decodes cleanly but is outside the IA5 range
        Asn1String.IA5(byteArrayOf(0xc2.toByte(), 0x80.toByte())).isValid shouldBe false
        shouldThrow<Asn1Exception> { Asn1String.IA5(PAD.toString()) }
    }

    // ---- Fix 3: UTF8 ----

    "UTF8 (A) accepts a genuine U+FFFD — via both the String and the raw-bytes path" {
        shouldNotThrowAny { Asn1String.UTF8(REPLACEMENT.toString()) }
        Asn1String.UTF8(REPLACEMENT.toString()).isValid shouldBe true
        // the canonical UTF-8 encoding of U+FFFD is EF BF BD
        val efbfbd = byteArrayOf(0xef.toByte(), 0xbf.toByte(), 0xbd.toByte())
        Asn1String.UTF8(efbfbd).let {
            it.isValid shouldBe true
            it.value shouldBe REPLACEMENT.toString()
        }
    }

    "UTF8 (B) rejects malformed byte sequences and accepts well-formed multi-byte" {
        // malformed: lone continuation byte, truncated lead byte, overlong '/' (C0 AF)
        Asn1String.UTF8(byteArrayOf(0x80.toByte())).isValid shouldBe false
        Asn1String.UTF8(byteArrayOf(0xc3.toByte())).isValid shouldBe false
        Asn1String.UTF8(byteArrayOf(0xc0.toByte(), 0xaf.toByte())).isValid shouldBe false

        // well-formed: "ä" == C3 A4, and plain ASCII
        Asn1String.UTF8(byteArrayOf(0xc3.toByte(), 0xa4.toByte())).let {
            it.isValid shouldBe true
            it.value shouldBe "ä"
        }
        Asn1String.UTF8(byteArrayOf(0x41)).isValid shouldBe true       // 'A'
    }

    // ---- Best-effort types (Teletex, General, Graphic): never reject potentially-valid input ----
    //
    // Their true repertoires are multi-byte / ISO 2022 and cannot be validated exactly, so isValid returns
    // `true` for a recognized subset and `null` ("unknown") otherwise, and NEVER `false`. The String constructor
    // must therefore never throw for these types.

    // Each `.isValid` below is reached through the throwing `String` constructor, so a `null` result also proves
    // the constructor did not reject the input.

    "Graphic recognizes its 7-bit subset and never rejects higher graphic characters" {
        Asn1String.Graphic("abc123").isValid shouldBe true          // recognized 0x20-0x7e subset
        // é (Latin-1) and CJK are legitimate graphic characters outside the recognized subset -> null, not false
        Asn1String.Graphic("é23456").isValid shouldBe null
        Asn1String.Graphic("テスト").isValid shouldBe null
    }

    "General recognizes its 7-bit subset (incl. DELETE) and never rejects higher content" {
        Asn1String.General("abc").isValid shouldBe true
        Asn1String.General(DEL.toString()).isValid shouldBe true    // DELETE is a member of GeneralString
        Asn1String.General("é").isValid shouldBe null               // 8-bit content: unknown, not rejected
    }

    "Teletex recognizes its Latin-1 subset and never rejects beyond it" {
        Asn1String.Teletex("é").isValid shouldBe true               // within the Latin-1 recognized subset
        Asn1String.Teletex("テスト").isValid shouldBe null           // beyond Latin-1: unknown, not rejected
    }
}
