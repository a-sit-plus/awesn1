// SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(ExperimentalStdlibApi::class, InternalAwesn1Api::class)

package at.asitplus.awesn1


import at.asitplus.awesn1.Asn1Element.Tag.Template.Companion.withClass
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.encoding.internal.Sink
import at.asitplus.awesn1.encoding.internal.Source
import at.asitplus.awesn1.encoding.internal.decapsulateOrSelf
import kotlinx.serialization.Serializable
import kotlin.concurrent.Volatile
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/** A node (element + indentation) for the [DeepRecursiveFunction] string renderer (see [Asn1Element.renderTo]). */
private class RenderNode(val element: Asn1Element, val indent: Int)

/**
 * Shared, stateless [DeepRecursiveFunction] backing [Asn1Structure.contentLengthLong]: a child-first post-order
 * that populates each visited structure's `cachedContentLength` (summing children's `overallLengthLong` with
 * [plusExact]). Stack-safe (heap-allocated recursion) and safe to share — each invocation gets its own stack.
 *
 */
// Here, DeepRevursiveFunction was faster than hand-rolled. But should be re-evaluated at some point, since we now got rid of the lazies
private val computeContentLength: DeepRecursiveFunction<Asn1Structure, Unit> = DeepRecursiveFunction { n ->
    if (n.cachedContentLength < 0) {
        var sum = 0L
        for (c in n.children) {
            when (c) {
                is Asn1Structure if c.cachedContentLength < 0 -> callRecursive(c)
                is Asn1EncapsulatingOctetString if c._sequence.cachedContentLength < 0 -> callRecursive(c._sequence)
                else -> {/*fall through*/}
            }
            sum = sum.plusExact(c.overallLengthLong)
        }
        n.cachedContentLength = sum
    }
}

/**
 * Default character cap for `toString`/`prettyPrint`; output beyond this is truncated with [RENDER_TRUNCATION_MARKER].
 * Exists because in-memory `String`/`StringBuilder` are `Int`-bounded on the JVM. Callers streaming to a sink (see the
 * `kxs-io` `toString`/`prettyPrint` extensions) may pass a larger limit.
 */
@InternalAwesn1Api
const val MAX_RENDER_CHARS: Long = (1 shl 20).toLong()
private const val RENDER_TRUNCATION_MARKER = " … (output truncated)"

/**
 * Base ASN.1 data class. Can either be a primitive (holding a value), or a structure (holding other ASN.1 elements)
 */
@Serializable(with = Asn1ElementFallbackBase64Serializer::class)
sealed class Asn1Element(
    val tag: Tag
) {

    // equals/hashCode compare the (canonical) DER encoding — equivalent to the former per-type structural
    // comparison, but stack-safe (derEncoded is iterative) and uniform. `final` so subtypes don't reintroduce
    // recursive overrides.
    final override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Asn1Element) return false
        return derEncoded.contentEquals(other.derEncoded)
    }

    companion object {
        /**
         * Convenience method to directly parse a HEX-string representation of DER-encoded data.
         * Ignores and strips all whitespace.
         *
         * @param limit the maximum allowed total number of encoded DER bytes to consume. Defaults to null to use allow reading the full contents of the string.
         * This limit is enforced before reading or peeking from the underlying source.
         * @throws [Throwable] all sorts of errors on invalid input
         */
        @Throws(Throwable::class)
        fun parseFromDerHexString(derEncoded: String, limit: Long? = null): Asn1Element {
            // Single-pass strip (':' and whitespace) + uppercase, enforcing `limit` *while* cleaning so the
            // decoded ByteArray can never exceed it. Old one causd quadratic memory growth
            val cleaned = StringBuilder(
                if (limit != null) minOf(derEncoded.length.toLong(), limit * 2 + 2).toInt() else derEncoded.length
            )
            for (c in derEncoded) {
                if (c == ':' || c.isWhitespace()) continue
                cleaned.append(c.uppercaseChar())
                // two hex chars per byte: abort as soon as the decoded size would exceed the limit
                if (limit != null && cleaned.length.toLong() > limit * 2)
                    throw Asn1Exception("Hex input decodes to more than the $limit-byte limit")
            }
            val byteArray = cleaned.toString().hexToByteArray(HexFormat.UpperCase)
            return Asn1Element.parse(byteArray, limit)
        }
    }

    /**
     * Length (already properly encoded into a byte array for writing as ASN.1) **of the contained data**, not the whole
     * ASN.1 element.
     * For a primitive, this is just the size of the held bytes.
     * For a structure, it is the sum of the number of bytes needed to encode all held child nodes.
     */
    // Sentinel-cached instead of `by lazy`: avoids a per-element SynchronizedLazyImpl (+ its retained initializer
    // closure) for a value derived from the already-cached length. Benign idempotent race, same @Volatile posture
    // as cachedContentLength/cachedHash.
    @Volatile
    private var encodedLengthCache: ByteArray? = null
    val encodedLength: ByteArray
        get() = encodedLengthCache ?: contentLengthLong.encodeLength().also { encodedLengthCache = it }

    /**
     * Length of the contained data as a [Long]. This is the overflow-safe source of truth; for a primitive it
     * is the size of the held bytes, for a structure the sum of the encoded sizes of all child nodes.
     */
    abstract val contentLengthLong: Long

    /**
     * Length (as a plain `Int` to work with it in code) of the contained data. Guarded: throws [Asn1Exception]
     * if [contentLengthLong] exceeds [Int.MAX_VALUE] (a >2 GiB aggregate) rather than silently overflowing.
     * For such elements use [contentLengthLong].
     */
    val contentLength: Int get() = contentLengthLong.toIntChecked("content length")

    /**
     * Total number of bytes required to represent this element when encoding to ASN.1, as a [Long]. Computed
     * arithmetically from the (sentinel-cached) [contentLengthLong] — no `lazy`, no materialized length array — so
     * the length post-order ([Asn1Structure.contentLengthLong]) can sum children without per-node lock/allocation.
     */
    val overallLengthLong: Long
        get() = contentLengthLong.plusExact(tag.encodedTagLength.toLong())
            .plusExact(lengthEncodedSize(contentLengthLong).toLong())

    /**
     * Total number of bytes required to represent this element when encoding to ASN.1. Guarded: throws
     * [Asn1Exception] if [overallLengthLong] exceeds [Int.MAX_VALUE]. For such elements use [overallLengthLong].
     */
    val overallLength: Int get() = overallLengthLong.toIntChecked("overall length")


    /**
     * DER-encoded representation of this ASN.1 element.
     *
     * NOT retained on structures: this base getter RE-ENCODES on every access (stack-safe — [encodeTreeTo] is an
     * iterative walk that terminates at the cached leaf primitives). Only [Asn1Primitive] (true leaves, incl. raw
     * OCTET STRINGs) overrides this to cache. This keeps retained memory ~O(input) and avoids the O(input²) blowup
     * of deeply nested structures/OCTET STRINGs. Callers who want a stable buffer should hold onto the result
     * themselves (the bytes are immutable).
     */
    open val derEncoded: ByteArray get() = throughBuffer { encodeTreeTo(it) }


    protected abstract fun doEncode(sink: Sink)

    @InternalAwesn1Api
    fun encodeTo(sink: Sink) = encodeTreeTo(sink)

    /**
     * Stack-safe DER encoder: an iterative explicit-stack pre-order walk streaming into [sink], so a deeply nested
     * element cannot overflow the call stack. Structures (and encapsulating OCTET STRINGs) write their header then
     * push their children; primitive leaves write tag/length/content directly. `protected` so [Asn1Primitive] can
     * reuse it for its cached [derEncoded].
     */
    protected fun encodeTreeTo(sink: Sink) {
        val stack = ArrayDeque<Asn1Element>().apply { addLast(this@Asn1Element) }
        while (stack.isNotEmpty()) when (val e = stack.removeLast()) {
            is Asn1Structure -> {
                sink.write(e.tag.encodedTag)
                sink.encodeLength(e.contentLengthLong) // direct length write — no per-node array allocation
                for (i in e.children.indices.reversed()) stack.addLast(e.children[i])
            }

            // an encapsulating OCTET STRING is byte-identical to `04 || len || <children encoded>`; encode it
            // STRUCTURALLY (header + push children) — never via its `content` provider — so deep encapsulation
            // stays iterative AND never materializes a per-layer content copy (this is the O(input²) fix).
            is Asn1EncapsulatingOctetString -> {
                sink.write(e.tag.encodedTag)
                sink.encodeLength(e.contentLengthLong)
                for (i in e.children.indices.reversed()) stack.addLast(e.children[i])
            }

            is Asn1Primitive -> e.doEncode(sink)
        }
    }

    override fun toString(): String = toString(MAX_RENDER_CHARS)

    /** Compact single-line rendering, truncated at [limit] characters with a marker (see [renderTo]). */
    fun toString(limit: Long): String = throughBuffer { renderTo(it, pretty = false, limit = limit) }.decodeToString()

    /** Verbose, indented human-readable tree, truncated at [limit] characters with a marker (see [renderTo]). */
    fun prettyPrint(limit: Long = MAX_RENDER_CHARS): String =
        throughBuffer { renderTo(it, pretty = true, limit = limit) }.decodeToString()

    /**
     * Stack-safe renderer that writes this element's compact ([pretty] = `false`) or indented ([pretty] = `true`)
     * string form as UTF-8 into [out], stopping after [limit] characters (appending a truncation marker).
     * Expressed with [DeepRecursiveFunction] so deep nesting cannot overflow the call stack; reuses the per-node
     * [prettyPrintHeader]/[prettyPrintTrailer]/[contentToString] so output is unchanged for ordinary elements.
     *
     * The character [limit] is required because in-memory `String`/`StringBuilder` are `Int`-bounded: the in-memory
     * [toString]/[prettyPrint] pass [MAX_RENDER_CHARS], while streaming to a `kotlinx.io.Sink` (the `kxs-io`
     * extensions) can pass a larger value. Per-leaf content is rendered bounded (and clamped to `Int`) so a single
     * huge primitive never materializes a giant transient. The limit also bounds the descent, since each header
     * carries its own indentation and output therefore grows with depth.
     */
    @InternalAwesn1Api
    fun renderTo(out: Sink, pretty: Boolean, limit: Long) {
        var emitted = 0L
        fun emit(text: String) {
            if (emitted >= limit) return
            val room = limit - emitted
            if (text.length <= room) {
                out.write(text.encodeToByteArray()); emitted += text.length
            } else {
                val take = room.toInt() // room < text.length <= Int.MAX_VALUE, so it fits
                if (take > 0) out.write(text.substring(0, take).encodeToByteArray())
                out.write(RENDER_TRUNCATION_MARKER.encodeToByteArray())
                emitted = limit
            }
        }
        DeepRecursiveFunction<RenderNode, Unit> { node ->
            if (emitted < limit) {
                val e = node.element
                val ind = node.indent
                when (e) {
                    is Asn1Structure -> if (pretty) {
                        emit(e.prettyPrintHeader(ind))
                        emit("\n" + (" " * ind) + "{\n")
                        e.children.forEachIndexed { i, c -> if (i != 0) emit("\n"); callRecursive(RenderNode(c, ind + 2)) }
                        emit("\n" + (" " * ind) + "}")
                        emit(e.prettyPrintTrailer(ind))
                    } else {
                        if (e is Asn1CustomStructure) emit("${e.tag.tagClass}")
                        emit(e.prettyPrintHeader(0)); emit(e.toStringPrefix()); emit(", children=[")
                        e.children.forEachIndexed { i, c -> if (i != 0) emit(", "); callRecursive(RenderNode(c, 0)) }
                        emit("]" + e.prettyPrintTrailer(0))
                    }

                    is Asn1Primitive -> {
                        emit(e.prettyPrintHeader(if (pretty) ind else 0))
                        emit(" ")
                        // render content bounded to the remaining budget so a huge primitive never builds a giant String;
                        // clamp the build budget to Int (a String is Int-bounded) and reserve headroom for the suffix
                        val content = e.content
                        val buildRoom = (limit - emitted).coerceIn(0, Int.MAX_VALUE.toLong()).toInt()
                        emit(
                            if (content.size.toLong() * 2 <= buildRoom.toLong()) e.contentToString() // small: full (semantic) render
                            else content.copyOf(((buildRoom - 64) / 2).coerceIn(0, content.size))
                                .toHexString(HexFormat.UpperCase) + "…(${content.size} bytes)"
                        )
                        emit(e.prettyPrintTrailer(if (pretty) ind else 0))
                    }
                }
            }
        }(RenderNode(this, 0))
    }

    protected abstract fun contentToString(): String

    protected open fun prettyPrintHeader(indent: Int) =
        "(tag=${tag}" + ", length=${contentLengthLong}" + ", overallLength=${overallLengthLong})"

    protected open fun prettyPrintTrailer(indent: Int) = ""

    protected operator fun String.times(op: Int): String = repeat(op)


    /**
     * Convenience method to directly produce an HEX string of this element's ASN.1 representation
     */
    fun toDerHexString(lineLen: Int? = null) = derEncoded.toHexString(HexFormat.UpperCase)
        .let { if (lineLen == null) it else it.chunked(lineLen).joinToString(separator = "\n") }


    /**
     * Convenience function to cast this element to an [Asn1Primitive]
     * @throws Asn1StructuralException if this element is not a primitive
     */
    @Throws(Asn1StructuralException::class)
    fun asPrimitive() = thisAs<Asn1Primitive>()

    /**
     * Convenience function to cast this element to an [Asn1Structure]
     * @throws Asn1StructuralException if this element is not a structure
     */
    @Throws(Asn1StructuralException::class)
    fun asStructure() = thisAs<Asn1Structure>()

    /**
     * Convenience function to cast this element to an [Asn1Sequence]
     * @throws Asn1StructuralException if this element is not a sequence
     */
    @Throws(Asn1StructuralException::class)
    fun asSequence() = thisAs<Asn1Sequence>()

    /**
     * Convenience function to cast this element to an [Asn1SequenceOf]
     * @throws Asn1StructuralException if this element is not a sequence-of
     */
    @Throws(Asn1StructuralException::class)
    fun asSequenceOf() = thisAs<Asn1SequenceOf>()

    /**
     * Convenience function to cast this element to an [Asn1Set]
     * @throws Asn1StructuralException if this element is not a set
     */
    @Throws(Asn1StructuralException::class)
    fun asSet() = thisAs<Asn1Set>()

    /**
     * Convenience function to cast this element to an [Asn1SetOf]
     * @throws Asn1StructuralException if this element is not a set-of
     */
    @Throws(Asn1StructuralException::class)
    fun asSetOf() = thisAs<Asn1SetOf>()

    /**
     * Convenience function to cast this element to an [Asn1ExplicitlyTagged]
     * @throws Asn1StructuralException if this element is not an explicitly tagged structure
     */
    @Throws(Asn1StructuralException::class)
    fun asExplicitlyTagged() = thisAs<Asn1ExplicitlyTagged>()

    /**
     * Convenience function to cast this element to an [Asn1EncapsulatingOctetString]
     * @throws Asn1StructuralException if this element is not an octet string containing a valid ASN.1 structure
     */
    @Throws(Asn1StructuralException::class)
    fun asEncapsulatingOctetString() = thisAs<Asn1EncapsulatingOctetString>()

    /**
     * Convenience function to cast this element to an [Asn1OctetString]
     * @throws Asn1StructuralException if this element is not an octet string
     */
    @Throws(Asn1StructuralException::class)
    fun asOctetString() = thisAs<Asn1OctetString>()


    @Throws(Asn1StructuralException::class)
    private inline fun <reified T> thisAs(): T =
        (this as? T)
            ?: throw Asn1StructuralException("${this::class.simpleName} cannot be reinterpreted as ${T::class.simpleName}.")


    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Element.
     * NOTE: The [TagClass] of the provided [tag] will be used! If you want the result to have [TagClass.CONTEXT_SPECIFIC],
     * use `element withImplicitTag (tag withClass TagClass.CONTEXT_SPECIFIC)`!. If a CONSTRUCTED Tag is applied to an ASN.1 Primitive,
     * the CONSTRUCTED bit is overridden and set to zero.
     */
    @Suppress("NOTHING_TO_INLINE")
    inline infix fun withImplicitTag(tag: Tag): Asn1Element = when (this) {
        is Asn1Structure -> {
            if (tag.isConstructed) Asn1CustomStructure(
                children,
                tag.tagValue,
                tag.tagClass,
                sortChildren = false,
                shouldBeSorted = shouldBeSorted
            ) else Asn1CustomStructure.asPrimitive(
                children,
                tag.tagValue,
                tag.tagClass,
                sortChildren = false,
                shouldBeSorted = shouldBeSorted
            )
        }

        is Asn1Primitive -> Asn1Primitive(tag without CONSTRUCTED, content)
    }

    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Element.
     * Sets the class of the resulting structure to [TagClass.CONTEXT_SPECIFIC]
     */
    @Suppress("NOTHING_TO_INLINE")
    inline infix fun withImplicitTag(tagValue: ULong) = withImplicitTag(tagValue withClass TagClass.CONTEXT_SPECIFIC)


    /**
     * Creates a new implicitly tagged ASN.1 Element from this ASN.1 Structure.
     * If the provided [template]'s tagClass is not set, the class of the resulting structure defaults to [TagClass.CONTEXT_SPECIFIC].
     * If a CONSTRUCTED Tag is applied to an ASN.1 Primitive, the CONSTRUCTED bit is overridden and set to zero.
     */
    @Suppress("NOTHING_TO_INLINE")
    inline infix fun withImplicitTag(template: Tag.Template) = when (this) {
        is Asn1Structure -> withImplicitTag(
            Tag(
                tagValue = template.tagValue,
                tagClass = template.tagClass ?: TagClass.CONTEXT_SPECIFIC,
                constructed = template.constructed ?: tag.isConstructed
            )
        )

        is Asn1Primitive -> Asn1Primitive(
            Tag(template.tagValue, tagClass = template.tagClass ?: TagClass.CONTEXT_SPECIFIC, constructed = false),
            content
        )
    }

    // Cache only the 4-byte hash, not the bytes — structures still retain no encoded bytes, but hashCode stays
    // O(1) after first use (so structures used as hash-map keys don't re-encode per lookup). Benign idempotent
    // race, same @Volatile posture as cachedContentLength. equals still recomputes (it needs the actual bytes).
    @Volatile
    private var cachedHash: Int = 0 // 0 = unset sentinel
    final override fun hashCode(): Int {
        var h = cachedHash
        if (h == 0) {
            h = derEncoded.contentHashCode()
            if (h == 0) h = 1 // don't re-derive when the real hash legitimately is 0
            cachedHash = h
        }
        return h
    }


    @ConsistentCopyVisibility
    data class Tag internal constructor(
        val tagValue: ULong,
        val encodedTag: ByteArray
    ) : Comparable<Tag> {

        /**
         * The length (in bytes) of this tag when encoded according to DER
         */
        val encodedTagLength: Int = encodedTag.size

        /**
         * Creates a copy of this tag, overriding [tagValue], but keeping [isConstructed] and [tagClass]
         */
        infix fun withNumber(number: ULong) = Tag(number, constructed = isConstructed, tagClass = tagClass)

        constructor(tagValue: ULong, constructed: Boolean, tagClass: TagClass = TagClass.UNIVERSAL) : this(
            tagValue, encode(tagClass, constructed, tagValue)
        )

        // Eager (not `by lazy`): deriving the class is one byte read + enum lookup, and the init below reads it
        // anyway, so laziness only bought a per-Tag SynchronizedLazyImpl + retained closure. Real-world inputs carry
        // many distinct Tags, so that scaffolding dominated; `TagClass` is an interned enum, so this field is just a
        // shared reference.
        val tagClass: TagClass = checkNotNull(TagClass.fromByte(encodedTag.first()).getOrNull()) {
            "An Illegal Tag class has been found. This should be impossible!"
        }

        init {
            if (tagValue == 0uL && tagClass == TagClass.UNIVERSAL) {
                throw Asn1Exception("Illegal DER tag: universal tag 0 (end-of-contents) is not allowed")
            }
            if (tagValue == 15uL && tagClass == TagClass.UNIVERSAL) {
                throw Asn1Exception("Illegal DER tag: universal tag 0x0F is not allowed")
            }
        }

        companion object {
            private fun encode(tagClass: TagClass, constructed: Boolean, tagValue: ULong): ByteArray {
                val derEncoded: ByteArray =
                    if (tagValue <= 30u) {
                        byteArrayOf(tagValue.toUByte().toByte())
                    } else {
                        byteArrayOf(0b11111, *tagValue.toAsn1VarInt())
                    }

                derEncoded[0] = derEncoded[0].toUByte()
                    .let { if (constructed) (it or BERTags.CONSTRUCTED) else it }
                    .let { it or tagClass.berTag }
                    .toByte()
                return derEncoded
            }

            val SET = Tag(tagValue = BERTags.SET.toULong(), constructed = true)
            val SEQUENCE = Tag(tagValue = BERTags.SEQUENCE.toULong(), constructed = true)

            @OptIn(ExperimentalObjCName::class)
            @ObjCName("ASN1_NULL") //workaround KT-33092
            val NULL = Tag(tagValue = BERTags.ASN1_NULL.toULong(), constructed = false)
            val BOOL = Tag(tagValue = BERTags.BOOLEAN.toULong(), constructed = false)
            val INT = Tag(tagValue = BERTags.INTEGER.toULong(), constructed = false)
            val REAL = Tag(tagValue = BERTags.REAL.toULong(), constructed = false)
            val OID = Tag(tagValue = BERTags.OBJECT_IDENTIFIER.toULong(), constructed = false)
            val ENUM = Tag(tagValue = BERTags.ENUMERATED.toULong(), constructed = false)

            val OCTET_STRING = Tag(tagValue = BERTags.OCTET_STRING.toULong(), constructed = false)
            val BIT_STRING = Tag(tagValue = BERTags.BIT_STRING.toULong(), constructed = false)

            val STRING_UTF8 = Tag(tagValue = BERTags.UTF8_STRING.toULong(), constructed = false)
            val STRING_UNIVERSAL = Tag(tagValue = BERTags.UNIVERSAL_STRING.toULong(), constructed = false)
            val STRING_IA5 = Tag(tagValue = BERTags.IA5_STRING.toULong(), constructed = false)
            val STRING_BMP = Tag(tagValue = BERTags.BMP_STRING.toULong(), constructed = false)
            val STRING_T61 = Tag(tagValue = BERTags.T61_STRING.toULong(), constructed = false)
            val STRING_PRINTABLE = Tag(tagValue = BERTags.PRINTABLE_STRING.toULong(), constructed = false)
            val STRING_NUMERIC = Tag(tagValue = BERTags.NUMERIC_STRING.toULong(), constructed = false)
            val STRING_VISIBLE = Tag(tagValue = BERTags.VISIBLE_STRING.toULong(), constructed = false)
            val STRING_GENERAL = Tag(tagValue = BERTags.GENERAL_STRING.toULong(), constructed = false)
            val STRING_GRAPHIC = Tag(tagValue = BERTags.GRAPHIC_STRING.toULong(), constructed = false)
            val STRING_UNRESTRICTED = Tag(tagValue = BERTags.UNRESTRICTED_STRING.toULong(), constructed = false)
            val STRING_VIDEOTEX = Tag(tagValue = BERTags.VIDEOTEX_STRING.toULong(), constructed = false)

            val TIME_GENERALIZED = Tag(tagValue = BERTags.GENERALIZED_TIME.toULong(), constructed = false)
            val TIME_UTC = Tag(tagValue = BERTags.UTC_TIME.toULong(), constructed = false)

            val entries: Iterable<Tag> by lazy {
                setOf(
                    SET,
                    SEQUENCE,
                    NULL,
                    BOOL,
                    INT,
                    REAL,
                    OID,
                    ENUM,
                    OCTET_STRING,
                    BIT_STRING,
                    STRING_UTF8,
                    STRING_UNIVERSAL,
                    STRING_IA5,
                    STRING_BMP,
                    STRING_T61,
                    STRING_PRINTABLE,
                    STRING_NUMERIC,
                    STRING_VISIBLE,
                    TIME_GENERALIZED,
                    TIME_UTC
                )
            }

        }

        val name
            get() = when (this) {
                SET -> "SET"
                SEQUENCE -> "SEQUENCE"
                NULL -> "NULL"
                BOOL -> "BOOLEAN"
                INT -> "INTEGER"
                REAL -> "REAL"
                OID -> "OBJECT IDENTIFIER"
                ENUM -> "ENUMERATED"
                OCTET_STRING -> "OCTET STRING"
                BIT_STRING -> "BIT STRING"
                STRING_UTF8 -> "UTF8 STRING"
                STRING_UNIVERSAL -> "UNIVERSAL STRING"
                STRING_IA5 -> "IA5 STRING"
                STRING_BMP -> "BMP STRING"
                STRING_T61 -> "T61 STRING"
                STRING_PRINTABLE -> "PRINTABLE STRING"
                STRING_NUMERIC -> "NUMERIC STRING"
                STRING_VISIBLE -> "VISIBLE STRING"
                TIME_GENERALIZED -> "GENERALIZED TIME"
                TIME_UTC -> "UTC TIME"
                else -> null
            }


        val isConstructed get() = encodedTag.first().toUByte().isConstructed()

        internal val isExplicitlyTagged get() = isConstructed && tagClass == TagClass.CONTEXT_SPECIFIC

        override fun toString(): String =
            "${tagClass.let { if (it == TagClass.UNIVERSAL) "" else it.name + " " }}${tagValue}${if (isConstructed) " CONSTRUCTED" else ""}" +
                    (" (=${encodedTag.toHexString(HexFormat.UpperCase)})" + (name?.let { " ($it)" } ?: ""))

        /**
         * As per ITU-T X.680 8824-1 8.6
         * (class, then tag number). The constructed bit is intentionally ignored for canonical
         * tag ordering.
         */
        override fun compareTo(other: Tag) = EncodedTagComparator.compare(this, other)

        private object EncodedTagComparator : Comparator<Tag> {
            override fun compare(a: Tag, b: Tag): Int {
                val classCompare = a.tagClass.ordinal.compareTo(b.tagClass.ordinal)
                if (classCompare != 0) return classCompare
                //now, we're down to numbers
                return a.tagValue.compareTo(b.tagValue)
            }

        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Tag) return false
            if (!encodedTag.contentEquals(other.encodedTag)) return false

            return true
        }

        override fun hashCode(): Int = encodedTag.contentHashCode()

        /**
         * creates a new Tag from this object, overriding the class. Useful for implicitTagging (see [Asn1Structure.withImplicitTag])
         */
        infix fun withClass(tagClass: TagClass) =
            Tag(this.tagValue, tagClass = tagClass, constructed = this.isConstructed)

        /**
         * creates a new Tag from this object, negating the passed property. Useful for implicitTagging (see [Asn1Structure.withImplicitTag]).
         * This is a NOOP for tag that don't have this bit set.
         */
        infix fun without(negated: TagProperty): Tag = when (negated) {
            CONSTRUCTED -> Tag(this.tagValue, tagClass = this.tagClass, constructed = false)
        }

        /**
         * A tag with optional tagClass and optional constructed indicator. Used for ASN.1 builder DSL
         */
        class Template(val tagValue: ULong, val tagClass: TagClass?, val constructed: Boolean?) {

            /**
             * Creates a new tag template from this template, negating the passed property
             */
            @Suppress("NOTHING_TO_INLINE")
            inline infix fun without(negated: TagProperty) = when (negated) {
                is CONSTRUCTED -> Template(this.tagValue, this.tagClass, false)
            }

            companion object {
                /**
                 * Convenience function to construct a tag template from an ULong tag value and class
                 */
                @Suppress("NOTHING_TO_INLINE")
                inline infix fun ULong.withClass(tagClass: TagClass) =
                    Template(tagValue = this, tagClass = tagClass, constructed = null)

                /**
                 * Convenience function to construct a tag from an ULong tag value and property
                 */
                @Suppress("NOTHING_TO_INLINE")
                inline infix fun ULong.without(negated: TagProperty) = when (negated) {
                    is CONSTRUCTED -> Template(tagValue = this, tagClass = null, constructed = false)
                }

            }

        }
    }
}

/**
 * asserts that this element's tag matches [tag].
 *
 * @throws Asn1TagMismatchException on failure
 */
@Throws(Asn1TagMismatchException::class)
inline fun <reified T : Asn1Element> T.assertTag(tag: Asn1Element.Tag): T {
    if (this.tag != tag) throw Asn1TagMismatchException(tag, this.tag)
    return this
}

/**
 * Asserts only the tag number, but neither class, nor CONSTRUCTED bit.
 * @see assertTag
 * @throws Asn1TagMismatchException on failure
 */
@Throws(Asn1TagMismatchException::class)
inline fun <reified T : Asn1Element> T.assertTag(tagNumber: ULong): T = assertTag(tag withNumber tagNumber)

/**
 * ASN.1 NULL as constant
 */
//this MUST NOT be an object, because checks like `someAsn1Element is Asn1Null` would be legal but can never succeed
//checking the opposite way will make sense and will succeed, so an object would lead to cursed behaviour
//if we keep it a regular ol' val, the Asn1Element's tried and true equals check will always perform as expected
val Asn1Null = Asn1Primitive(Asn1Element.Tag.NULL, byteArrayOf())

/**
 * ASN.1 structure. Contains no data itself, but holds zero or more [mutableChildren]
 */
@Serializable(with = Asn1StructureFallbackBase64Serializer::class)
sealed class Asn1Structure(
    /**
     * The tag identifying this structure
     */
    tag: Tag,

    /**
     * This structure's child elements
     */
    mutableChildren: MutableList<Asn1Element>,
    /**
     * Whether this structure sorts child nodes or keeps them as-is.
     * This **should** be true for SET and SET OF, but is set to false for SET and SET OF elements parsed
     * from DER-encoded structures, because this has a chance of altering the structure for non-conforming DER-encoded
     * structures.
     */
    sortChildren: Boolean,

    /**
     * Indicates whether this structure should sort their child nodes by default. This is true for SET and for
     * all custom structure that enforce SET semantics. Note that it is impossible to infer this property correctly when
     * parsing custom structures. Therefore, it has no impact on [equals].
     */
    val shouldBeSorted: Boolean
) :
    Asn1Element(tag), Iterable<Asn1Element> {

    private object DerEncodedElementComparator : Comparator<Asn1Element> {
        // DER orders by the lexicographic order of the full encoding (tag||length||content). That equals: compare
        // the (prefix-free) tag bytes, then — for canonical DER, where numeric length order matches the length
        // encoding's byte order — the content length, then the content. Tag bytes and contentLengthLong are
        // cheap/cached, so for the common case (a heterogeneous SET whose members differ in tag or length) this
        // decides WITHOUT materializing the members' full encodings; only an exact tag+length tie falls back to the
        // full derEncoded compare (where the content bytes must be examined anyway).
        override fun compare(a: Asn1Element, b: Asn1Element): Int {
            val ta = a.tag.encodedTag; val tb = b.tag.encodedTag
            for (i in 0 until minOf(ta.size, tb.size)) {
                val c = ta[i].toUByte().compareTo(tb[i].toUByte())
                if (c != 0) return c
            }
            if (ta.size != tb.size) return ta.size.compareTo(tb.size) // prefix-free tags: rarely reached
            val lc = a.contentLengthLong.compareTo(b.contentLengthLong)
            if (lc != 0) return lc
            // identical tag and content length → the content decides; compare the full encodings
            val x = a.derEncoded; val y = b.derEncoded
            for (i in 0 until minOf(x.size, y.size)) {
                val c = x[i].toUByte().compareTo(y[i].toUByte())
                if (c != 0) return c
            }
            return x.size.compareTo(y.size)
        }
    }


    /**
     * This structure's child elements
     */
    val children: List<Asn1Element>
        field: MutableList<Asn1Element> = mutableChildren.apply { if (sortChildren) sortWith(DerEncodedElementComparator) }

    /**
     * Replaces the child at [index] in place. Internal-only: used by the parser to swap a raw OCTET STRING for
     * its [Asn1EncapsulatingOctetString] counterpart while decoding, before the tree is handed out. The
     * replacement is byte-identical and same-tag, so it does not alter this structure's encoding. Callers must
     * not have called `equals`/`hashCode` (directly or via hash collections) on this subtree before teh octet string iteration is through.
     */
    @Suppress("NOTHING_TO_INLINE")
    internal inline fun replaceChild(index: Int, node: Asn1Element) {
        @Suppress("UNCHECKED_CAST")
        children[index] = node
    }

    /**
     * indicated whether the structure's children are actually sorted.
     * This could be false for parsing non-compliant SETs, for example.
     */
    // Tri-state cache with `null` = "not yet computed", seeded at construction: when we sorted the children ourselves
    // (sortChildren), the answer is known to be `true` with zero computation. Otherwise it is computed on first read
    // — only prettyPrint of a SET reads it — and cached. The field is just a reference to the interned `true`/`false`
    // (no per-node allocation), no Lazy/closure; benign idempotent race, same @Volatile posture as
    // cachedContentLength/cachedHash. (replaceChild swaps are byte-identical/same-tag, so a cached result never goes stale.)
    @Volatile
    private var isActuallySortedCache: Boolean? = if (sortChildren) true else null
    val isActuallySorted: Boolean
        get() {
            isActuallySortedCache?.let { return it }
            val sorted = children.sortedWith(DerEncodedElementComparator) == children
            isActuallySortedCache = sorted
            return sorted
        }

    override operator fun iterator() = Iterator(isForward = true)
    fun reverseIterator() = Iterator(isForward = false)

    /**
     * An iterator over a list of [Asn1Element] children within an ASN.1 structure
     * Designed for traversing ASN.1 components in decoding/parsing scenarios
     * */
    inner class Iterator internal constructor(
        /** Whether this is a forward iterator */
        val isForward: Boolean
    ) : kotlin.collections.Iterator<Asn1Element> {

        /** Whether this is a reverse iterator */
        val isReverse get() = !isForward

        /** reference to the [Asn1Structure] this iterator belongs to*/
        val containingStructure: Asn1Structure get() = this@Asn1Structure

        /** The index of the last element returned by [next] */
        var currentIndex: Int =
            if (isForward) -1 else children.size
            private set

        /** The last element returned by [next]. Throws [NoSuchElementException] if [next] was not yet called. */
        val currentElement
            get() =
                try {
                    children[currentIndex]
                } catch (x: IndexOutOfBoundsException) {
                    throw NoSuchElementException(x.message)
                }

        private val step get() = if (isForward) 1 else -1

        private val nextIndex get() = currentIndex + step

        /**
         * Returns the next child held by this structure. Useful for iterating over its children when parsing complex structures.
         * @throws [NoSuchElementException] if no more children are available
         */
        override fun next(): Asn1Element {
            currentIndex = nextIndex
            return currentElement
        }

        /**
         * Exception-free version of [next]
         */
        fun nextOrNull() = if (hasNext()) next() else null

        /**
         * Returns `true` if more children can be retrieved by [next]. `false` otherwise
         */
        override fun hasNext() = if (isForward) (nextIndex < children.size) else (nextIndex >= 0)

        /**
         * Returns the next child that would be returned by a call to [next] without advancing to iterator.
         * If there are no more children, returns `null`.
         */
        fun peek() = if (hasNext()) children[nextIndex] else null

        /**
         * Returns an iterator with reversed direction.
         * Current iteration position is preserved.
         */
        fun reversed(): Iterator =
            Iterator(isForward = !isForward).also { it.currentIndex = this.currentIndex }
    }

    /**
     * Decodes the content of this ASN.1 structure using the provided [decoder] lambda.
     * This function gives a convenient way to decode ASN.1 structures by exposing an
     * iterator over the structure's children to the [decoder] lambda. Optionally, it enforces that
     * all children must be consumed. Use [decodeRethrowing] to automatically and consistently wrap exceptions
     * thrown during decoding in [Asn1Exception]s.
     */
    inline fun <T> decodeAs(requireFullConsumption: Boolean = true, decoder: Iterator.() -> T): T {
        val it = iterator()
        val result = it.decoder()
        if (requireFullConsumption && it.hasNext())
            throw Asn1StructuralException("Trailing data found in ASN.1 structure")
        return result
    }


    // sentinel-cached, computed child-before-parent by [computeContentLength] (a stack-safe DeepRecursiveFunction
    // post-order) so that forcing a deeply nested structure's length cannot overflow the call stack (the plain
    // recursive fold did); folded with plusExact so the Long sum cannot silently wrap on a >2 GiB aggregate.
    // @Volatile: the cache is a plain mutable Long, so concurrent first-time `contentLengthLong` calls on the same
    // element would otherwise race — a 64-bit write is not guaranteed atomic by the JMM (and is a data race on
    // Kotlin/Native), risking a torn, bogus length being cached. Volatile gives atomic, visible access; the
    // remaining race (two threads both running the idempotent walk) is harmless — both write the same value.
    @Volatile
    internal var cachedContentLength: Long = -1
    override val contentLengthLong: Long
        get() {
            if (cachedContentLength < 0) computeContentLength(this)
            return cachedContentLength
        }

    override fun doEncode(sink: Sink) {
        children.let { childElems ->
            sink.write(tag.encodedTag);
            sink.write(encodedLength);
            childElems.forEach { child -> child.encodeTo(sink) }
        }
    }

    /** The `SORTED`/`NON-COMPLIANT`/empty prefix used in [toString] (extracted so the renderer needn't recurse). */
    internal fun toStringPrefix(): String = when {
        shouldBeSorted && isActuallySorted -> "SORTED"
        shouldBeSorted && !isActuallySorted -> "NON-COMPLIANT (UNSORTED)"
        else -> ""
    }

    override fun contentToString(): String = "${toStringPrefix()}, children=$children"
}

/**
 * Explicit ASN.1 Tag. Can contain any number of [children]
 */
@Serializable(with = Asn1ExplicitlyTaggedFallbackBase64Serializer::class)
class Asn1ExplicitlyTagged
/**
 * @param tag the ASN.1 Tag to be used will be properly encoded to have [BERTags.CONSTRUCTED] and
 * [BERTags.CONTEXT_SPECIFIC] bits set)
 * @param children the child nodes to be contained in this tag
 *
 */
internal constructor(tag: ULong, children: MutableList<Asn1Element>) :
    Asn1Structure(
        Tag(tag, constructed = true, tagClass = TagClass.CONTEXT_SPECIFIC),
        children,
        sortChildren = false,
        shouldBeSorted = false
    ) {


    /**
     * Returns this [Asn1ExplicitlyTagged] children, if its tag matches [tag]
     *
     * @throws Asn1TagMismatchException if the tag does not match
     */
    @Throws(Asn1TagMismatchException::class)
    fun verifyTag(explicitTag: Tag): List<Asn1Element> {
        if (this.tag != explicitTag) throw Asn1TagMismatchException(explicitTag, this.tag)
        return this.children
    }

    /**
     * Returns this [Asn1ExplicitlyTagged] children, if its tag matches [tagNumber]
     *
     * @throws Asn1TagMismatchException if the tag does not match
     */
    @Throws(Asn1TagMismatchException::class)
    fun verifyTag(tagNumber: ULong): List<Asn1Element> = verifyTag(Asn1.ExplicitTag(tagNumber))

    /**
     * Exception-free version of [verifyTag]
     */
    fun verifyTagOrNull(tagNumber: ULong) = catchingUnwrapped { verifyTag(tagNumber) }.getOrNull()

    /**
     * Exception-free version of [verifyTag]
     */
    fun verifyTagOrNull(explicitTag: Tag) = catchingUnwrapped { verifyTag(explicitTag) }.getOrNull()

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "Tagged" + super.prettyPrintHeader(indent)
}

/**
 * ASN.1 SEQUENCE 0x30 ([BERTags.SEQUENCE] OR [BERTags.CONSTRUCTED])
 * @param children the elements to put into this sequence
 */
@Serializable(with = Asn1SequenceFallbackBase64Serializer::class)
open class Asn1Sequence protected constructor(
    mutableChildren: MutableList<Asn1Element>
) : Asn1Structure(Tag.SEQUENCE, mutableChildren, sortChildren = false, shouldBeSorted = false) {

    init {
        if (!tag.isConstructed) throw IllegalArgumentException("An ASN.1 Structure must have a CONSTRUCTED tag")
    }

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "Sequence" + super.prettyPrintHeader(indent)

    companion object {
        /**
         * Creates an instance of an ASN.1 SET structure from the given list of children.
         * If the `children` can be represented as an instance of [Asn1SequenceOf], that will be returned.
         * Otherwise, an [Asn1Sequence] is constructed.
         *
         * @param children The list of [Asn1Element] to be encapsulated in the SET structure.
         * @return An instance of [Asn1Sequence] or [Asn1SequenceOf] based on the input.
         */
        operator fun invoke(children: List<Asn1Element>) = adopting(children.toMutableList())

        /** Parser-only: an [Asn1Sequence]/[Asn1SequenceOf] backed directly by [children] (aliased, not copied). */
        internal fun adopting(children: MutableList<Asn1Element>): Asn1Sequence =
            if (children.isNotEmpty() && children.any { it.tag != children.first().tag }) Asn1Sequence(children)
            else Asn1SequenceOf.adopting(children)
    }
}

/**
 * ASN.1 SEQUENCE OF 0x30 ([BERTags.SEQUENCE] OR [BERTags.CONSTRUCTED])
 * A SEQUENCE whose members all share the same tag (tag-homogeneous).
 * When parsing DER, the parser will automatically produce an [Asn1SequenceOf] instead of a plain [Asn1Sequence]
 * if all children share a tag. **Note**: An empty parsed SEQUENCE is also emitted as [Asn1SequenceOf],
 * since an empty sequence inherently satisfies the tag-homogeneity constraint and [Asn1SequenceOf] is an [Asn1Sequence].
 *
 * @param children the elements to put into this sequence
 * @throws Asn1Exception if non-empty and children do not all share the same tag
 */
@Serializable(with = Asn1SequenceOfFallbackBase64Serializer::class)
class Asn1SequenceOf private constructor(
    /** The tag shared by all children. `null` if this SEQUENCE OF is empty. */
    val commonTag: Tag?,
    children: MutableList<Asn1Element>,
) : Asn1Sequence(children) {

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "SequenceOf" + super.prettyPrintHeader(indent)

    companion object {
        /**
         * @param children the elements of the sequence. Asserts that these are all of the same tag.
         */
        operator fun invoke(children: List<Asn1Element>) = adopting(children.toMutableList())

        /** Parser-only: an [Asn1SequenceOf] backed directly by [children] (aliased, not copied). */
        internal fun adopting(children: MutableList<Asn1Element>) = runRethrowing {
            val commonTag = children.firstOrNull()?.tag
            children.forEach {
                require(it.tag == commonTag) {
                    "SEQUENCE OF must only contain elements of the same tag (has ${it.tag} != $commonTag)"
                }
            }
            Asn1SequenceOf(commonTag, children)
        }

    }
}

/**
 * ASN1 structure (i.e. containing child nodes) with custom tag
 */
@Serializable(with = Asn1CustomStructureFallbackBase64Serializer::class)
class Asn1CustomStructure internal constructor(
    tag: Tag, children: MutableList<Asn1Element>, sortChildren: Boolean, shouldBeSorted: Boolean
) : Asn1Structure(tag, children, sortChildren, shouldBeSorted) {
    /**
     * ASN.1 CONSTRUCTED with custom tag
     * @param children the elements to put into this sequence
     * @param tag the custom tag to use
     * @param tagClass the tag class to use for this custom tag. defaults to [TagClass.UNIVERSAL]
     * @param sortChildren whether to sort the passed child nodes. defaults to false
     * @param shouldBeSorted whether the child nodes of this structure should be sorted according to this structure's definition.
     * Note that this information is lost when parsing custom structures!
     */
    constructor(
        children: List<Asn1Element>,
        tag: ULong,
        tagClass: TagClass = TagClass.UNIVERSAL,
        sortChildren: Boolean = false,
        shouldBeSorted: Boolean = false
    ) : this(Tag(tag, constructed = true, tagClass), children.toMutableList(), sortChildren, shouldBeSorted)

    /**
     * ASN.1 CONSTRUCTED with custom tag
     * @param children the elements to put into this sequence
     * @param tag the custom tag to use
     * @param tagClass the tag class to use for this custom tag. defaults to [TagClass.UNIVERSAL]
     * @param sortChildren whether to sort the passed child nodes. defaults to false
     * @param shouldBeSorted whether the child nodes of this structure should be sorted according to this structure's definition.
     * Note that this information is lost when parsing custom structures!
     */
    constructor(
        children: List<Asn1Element>,
        tag: UByte,
        tagClass: TagClass = TagClass.UNIVERSAL,
        sortChildren: Boolean = false,
        shouldBeSorted: Boolean = false
    ) : this(children, tag.toULong(), tagClass, sortChildren, shouldBeSorted)

    // toString's leading tag-class prefix is emitted per-node by the iterative renderer (see Asn1Element.toString)

    /**
     * Raw byte DER-encoded representation of this custom structure's children.
     * This property is `null` **unless** the `CONSTRUCTED` flag of this structure's tag is overridden to `false`.
     *
     * Recomputed on each access (not retained) — like every other structure, this node keeps no encoded bytes; the
     * result is immutable, so hold onto it yourself if you need a stable buffer.
     */
    val content: ByteArray?
        get() = if (!tag.isConstructed) throughBuffer { sink -> children.forEach { it.encodeTo(sink) } } else null

    override fun prettyPrintHeader(indent: Int) =
        (" " * indent) + tag.tagClass +
                " ${tag.tagValue}" +
                (if (!tag.isConstructed) " PRIMITIVE" else "") +
                " (=${tag.encodedTag.toHexString(HexFormat.UpperCase)}), length=${contentLengthLong}" +
                ", overallLength=${overallLengthLong}" +
                (content?.let { " ${it.toHexString(HexFormat.UpperCase)}" } ?: "")

    companion object {
        /**
         * ASN.1 Structure encoded as an ASN.1 Primitive (similar to OCTET STRING containing a valid ASN.1 Structure) with custom tag
         * @param children the elements to put into this sequence
         * @param tag the custom tag to use
         * @param tagClass the tag class to use for this custom tag. defaults to [TagClass.UNIVERSAL]
         * @param sortChildren whether to sort the passed child nodes. defaults to false
         */
        fun asPrimitive(
            children: List<Asn1Element>,
            tag: ULong,
            tagClass: TagClass = TagClass.UNIVERSAL,
            sortChildren: Boolean = false,
            shouldBeSorted: Boolean = false
        ) =
            Asn1CustomStructure(
                Tag(tag, constructed = false, tagClass),
                children.toMutableList(),
                sortChildren,
                shouldBeSorted = shouldBeSorted
            )
    }
}


@Deprecated("Replace with Asn1OctetString", ReplaceWith("Asn1OctetString(content)"))
typealias Asn1PrimitiveOctetString = Asn1OctetString

/**
 * ASN.1 OCTET STRING 0x04 ([BERTags.OCTET_STRING]) containing arbitrary bytes
 *
 * May be an [Asn1EncapsulatingOctetString] if the contained bytes are valid ASN.1.
 */
@Serializable(with = Asn1OctetStringFallbackBase64Serializer::class)
sealed class Asn1OctetString : Asn1Primitive {

    /** This is an implementation detail, you shouldn't check for it */
    private class NotEncapsulating(content: ByteArray) : Asn1OctetString(content)

    private constructor(content: ByteArray) : super(Tag.OCTET_STRING, content)
    constructor(contentProvider: () -> ByteArray) : super(Tag.OCTET_STRING, contentProvider)

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "OCTET STRING " + super.prettyPrintHeader(0)

    companion object {
        /**
         * Constructs a raw (non-encapsulating) OCTET STRING from [content] without attempting to decode it.
         * Used by the parser, which decodes encapsulated content separately and iteratively.
         */
        internal fun nonEncapsulating(content: ByteArray): Asn1OctetString = NotEncapsulating(content)

        /**
         * Constructs an [Asn1OctetString].
         * Consumes exactly [length] bytes from [source].
         * Will construct an [Asn1EncapsulatingOctetString] if the contained bytes are valid ASN.1.
         */
        operator fun invoke(source: Source<*>, length: Long): Asn1OctetString {
            require(length <= Int.MAX_VALUE) { "Cannot read more than ${Int.MAX_VALUE} into an OCTET STRING" }
            return invoke(source.readByteArray(length.toInt()))
        }

        operator fun invoke(content: ByteArray): Asn1OctetString =
            //start raw, then iteratively peel any encapsulated ASN.1; per-layer fallback to raw
            NotEncapsulating(content).decapsulateOrSelf()
    }
}

/**
 * ASN.1 OCTET STRING 0x04 ([BERTags.OCTET_STRING]) containing an [Asn1Element]
 * @param children the elements to put into this sequence
 */
@Serializable(with = Asn1EncapsulatingOctetStringFallbackBase64Serializer::class)
class Asn1EncapsulatingOctetString private constructor(
    //the backing sequence is the single source of truth for children; reused for `isActuallySorted`,
    //`iterator`, and `decodeAs`. A raw and an encapsulating OCTET STRING encode to identical bytes, so a
    //decoding-time child replacement never changes this element's encoding.
    @PublishedApi
    internal val _sequence: Asn1Sequence,
) : Asn1OctetString(
    // `content` (the inner DER) is derived from the children and is NEVER forced on the parse/encode/equals path
    // (see the overrides below); it is realized lazily only on an explicit `content`/`prettyPrint` access.
    { throughBuffer { sink -> _sequence.children.forEach { it.encodeTo(sink) } } }
), Iterable<Asn1Element> {

    constructor(children: List<Asn1Element>) : this(Asn1Sequence(children))

    /**
     * This structure's child elements
     */
    val children: List<Asn1Element> get() = _sequence.children

    // Behaves as a STRUCTURE, not a primitive: it never retains its encoded bytes. The length is taken from the
    // children (so it does NOT force the `content` provider), and derEncoded re-encodes on each access (stack-safe
    // via the dedicated branch in encodeTreeTo). This is what keeps deeply nested encapsulation O(input), not
    // O(input²) — there is no per-layer `rawContent` copy any more.
    override val contentLengthLong: Long get() = _sequence.contentLengthLong
    override val derEncoded: ByteArray get() = throughBuffer { encodeTreeTo(it) }

    /**
     * Replaces the child at [index] in place. Internal-only; see [Asn1Structure.replaceChild] for the
     * decoding-time contract and constraints.
     */
    internal fun replaceChild(index: Int, node: Asn1Element) = _sequence.replaceChild(index, node)

    /**
     * indicated whether the structure's children are actually sorted.
     */
    val isActuallySorted: Boolean get() = _sequence.isActuallySorted

    /**
     * Decodes the content of this ASN.1 structure using the provided [decoder] lambda.
     * This function gives a convenient way to decode ASN.1 structures by exposing an
     * iterator over the structure's children to the [decoder] lambda. Optionally, it enforces that
     * all children must be consumed. Use [decodeRethrowing] to automatically and consistently wrap exceptions
     * thrown during decoding in [Asn1Exception]s.
     */
    inline fun <T> decodeAs(requireFullConsumption: Boolean = true, decoder: Asn1Structure.Iterator.() -> T): T =
        _sequence.decodeAs(requireFullConsumption, decoder)

    override fun iterator(): Asn1Structure.Iterator = _sequence.iterator()

    override fun prettyPrintHeader(indent: Int) =
        (" " * indent) + "OCTET STRING Encapsulating" + super.prettyPrintHeader(indent) + " " +
                content.toHexString(HexFormat.UpperCase)

    companion object {
        /**
         * Parser-only: an encapsulating OCTET STRING whose children [adopt][Asn1Sequence.adopting] the given list
         * without copying. Retains no encoded bytes — encoding is recomputed structurally on demand (stack-safe,
         * depth-independent) via the dedicated branch in [encodeTreeTo].
         */
        internal fun decapsulated(children: MutableList<Asn1Element>): Asn1EncapsulatingOctetString =
            Asn1EncapsulatingOctetString(Asn1Sequence.adopting(children))
    }
}


/**
 * ASN.1 SET 0x31 ([BERTags.SET] OR [BERTags.CONSTRUCTED])
 */
@Serializable(with = Asn1SetFallbackBase64Serializer::class)
open class Asn1Set protected constructor(children: MutableList<Asn1Element>, sortChildren: Boolean) :
    Asn1Structure(Tag.SET, children, sortChildren, shouldBeSorted = true) {

    init {
        if (!tag.isConstructed) throw IllegalArgumentException("An ASN.1 Structure must have a CONSTRUCTED tag")
    }


    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "Set" + super.prettyPrintHeader(indent)

    companion object {
        /**
         * Creates an instance of an ASN.1 SET structure from the given list of children.
         * If the `children` can be represented as an instance of [Asn1SetOf], that will be returned.
         * Otherwise, an [Asn1Set] is constructed.
         *
         * @param children The list of [Asn1Element] to be encapsulated in the SET structure.
         * @return An instance of [Asn1SetOf] or [Asn1Set] based on the input.
         */
        operator fun invoke(children: List<Asn1Element>) =
            Asn1SetOf.fromChildrenOrNull(children.toMutableList(), sortChildren = true)
                ?: Asn1Set(children.toMutableList(), sortChildren = true)

        /**
         * Explicitly discard DER requirements and DON'T sort children. Useful when parsing Structures which might not
         * conform to DER. Will produce an [Asn1SetOf] if children are empty or share the same tag.
         */
        internal fun fromPresorted(children: MutableList<Asn1Element>) =
            Asn1SetOf.fromChildrenOrNull(children, sortChildren = false) ?: Asn1Set(children, sortChildren = false)
    }
}

/**
 * ASN.1 SET OF 0x31 ([BERTags.SET] OR [BERTags.CONSTRUCTED])
 * A SET whose members all share the same tag (tag-homogeneous).
 * When parsing DER, the parser will automatically produce an [Asn1SetOf] instead of a plain [Asn1Set]
 * if all children share a tag. **Note**: An empty parsed SET is also emitted as [Asn1SetOf],
 * since an empty set inherently satisfies the tag-homogeneity constraint and [Asn1SetOf] is an [Asn1Set].
 *
 * @param children the elements to put into this set. will be automatically checked to have the same tag and sorted by DER-encoded bytes
 * @throws Asn1Exception if non-empty and children do not all share the same tag
 */
@Serializable(with = Asn1SetOfFallbackBase64Serializer::class)
class Asn1SetOf private constructor(
    /** The tag shared by all children. `null` if this SET OF is empty. */
    val commonTag: Tag?,
    children: MutableList<Asn1Element>,
    sortChildren: Boolean
) : Asn1Set(children, sortChildren) {

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "SetOf" + super.prettyPrintHeader(indent)

    companion object {

        /**
         * @param children the elements to put into this set. will be automatically checked to have the same tag and sorted by DER-encoded bytes
         */
        operator fun invoke(children: List<Asn1Element>) = runRethrowing {
            val commonTag = children.firstOrNull()?.tag
            children.forEach {
                require(it.tag == commonTag) {
                    "SET OF must only contain elements of the same tag (has ${it.tag} != $commonTag)"
                }
            }
            Asn1SetOf(commonTag, children.toMutableList(), sortChildren = true)
        }

        internal fun fromChildrenOrNull(children: MutableList<Asn1Element>, sortChildren: Boolean): Asn1SetOf? {
            val commonTag = children.firstOrNull()?.tag
            if (children.any { it.tag != commonTag }) return null
            return Asn1SetOf(commonTag, children, sortChildren)
        }
    }
}

/**
 * ASN.1 primitive. Holds no children, but [content] under [tag]
 */
@Serializable(with = Asn1PrimitiveFallbackBase64Serializer::class)
open class Asn1Primitive private constructor(
    tag: Tag,
    content: ByteArray?,
    contentProvider: (() -> ByteArray)
) : Asn1Element(tag) {

    constructor(tag: Tag, content: ByteArray) : this(tag, content, initImplError)
    constructor(tag: Tag, contentProvider: () -> ByteArray) : this(tag, null, contentProvider)

    init {
        if (tag.isConstructed) throw IllegalArgumentException("A primitive cannot have a CONSTRUCTED tag")
    }

    // Sentinel-cached instead of an `orLazy` delegate (no per-primitive Lazy/closure object).
    // hold then null-out to free lambda once inited. ugly mess but these tricks cut memory cost SIGNIFICANTLY
    private var contentProviderOrNull: (() -> ByteArray)? = if (content == null) contentProvider else null
    // props with explicit backing fields cannot have accessors, so we're left with this mess
    @Volatile
    private var contentCache: ByteArray? = content /*<- this is the ctor param, not the prop below*/
    val content: ByteArray
        get() = contentCache ?: contentProviderOrNull!!().also { /*order is important here!*/contentCache = it; contentProviderOrNull = null }

    override val contentLengthLong: Long get() = content.size.toLong()

    // leaves cache their encoding (and `content` above is already lazy-cached) — retention is bounded by leaf size.
    // Sentinel-cached instead of `by lazy` (no SynchronizedLazyImpl + closure per primitive); benign idempotent race,
    // Asn1EncapsulatingOctetString overrides `derEncoded` back to a non-caching recompute (it behaves as a structure).
    // cannot use explicit field because non-final, so we need this ecplicit ugly mess
    @Volatile
    private var derEncodedCache: ByteArray? = null
    override val derEncoded: ByteArray
        get() = derEncodedCache ?: throughBuffer { encodeTreeTo(it) }.also { derEncodedCache = it }

    override fun doEncode(sink: Sink) {
        sink.write(tag.encodedTag)
        sink.encodeLength(contentLengthLong) // direct length write — no per-node array allocation
        sink.write(content)
    }

    constructor(tagValue: ULong, content: ByteArray) : this(Tag(tagValue, false), content)

    constructor(tagValue: UByte, content: ByteArray) : this(tagValue.toULong(), content)

    override fun prettyPrintHeader(indent: Int) = (" " * indent) + "Primitive" + super.prettyPrintHeader(indent)

    override fun contentToString() = catchingUnwrapped {
        when (tag) {
            Tag.NULL -> ""
            Tag.BOOL -> decodeToBoolean().toString()
            Tag.INT -> decodeToInt().toString()
            Tag.REAL -> decodeToFloat().toString()
            Tag.OID -> ObjectIdentifier.decodeFromAsn1ContentBytes(content).let { oid ->
                KnownOIDs[oid]?.let { "$it ($oid)" } ?: oid.toString()
            }

            Tag.ENUM -> decodeToEnumOrdinal().toString()
            Tag.OCTET_STRING -> content.toHexString(HexFormat.UpperCase)
            Tag.BIT_STRING -> content.toHexString(HexFormat.UpperCase)
            Tag.STRING_UTF8 -> decodeToString()
            Tag.STRING_UNIVERSAL -> decodeToString()
            Tag.STRING_IA5 -> decodeToString()
            Tag.STRING_BMP -> decodeToString()
            Tag.STRING_T61 -> decodeToString()
            Tag.STRING_PRINTABLE -> decodeToString()
            Tag.STRING_NUMERIC -> decodeToString()
            Tag.STRING_VISIBLE -> decodeToString()
            Tag.TIME_GENERALIZED -> decodeToInstant().toString()
            Tag.TIME_UTC -> decodeToInstant().toString()
            else -> content.toHexString(HexFormat.UpperCase)
        }
    }.getOrElse { "Non-compliant content: 0x" + content.toHexString(HexFormat.UpperCase) }



    companion object {
        val initImplError: () -> ByteArray = { throw ImplementationError("ASN.1 Element construction") }
    }
}

@Throws(IllegalArgumentException::class)
/**
 * Number of bytes the DER length field occupies for a content length of [len], computed arithmetically without
 * materializing the length encoding. Mirrors the byte count produced by [Long.encodeLength]/[Sink.encodeLength].
 */
private inline fun lengthEncodedSize(len: Long): Int =
    if (len < 0x80) 1 else 1 + (Long.SIZE_BITS - len.countLeadingZeroBits() + Byte.SIZE_BITS - 1) / Byte.SIZE_BITS

internal fun Int.encodeLength(): ByteArray = toLong().encodeLength()

@Throws(IllegalArgumentException::class)
internal fun Long.encodeLength(): ByteArray {
    require(this >= 0)
    return when {
        (this < 0x80) -> byteArrayOf(this.toByte()) /* short form */
        else -> { /* long form */
            val length = this.toUnsignedByteArray()
            val lengthLength = length.size
            check(lengthLength < 0x80)
            byteArrayOf((lengthLength or 0x80).toByte(), *length)
        }
    }
}

/** Checked addition for non-negative ASN.1 lengths; throws [Asn1Exception] on [Long] overflow. */
@Suppress("NOTHING_TO_INLINE")
internal inline fun Long.plusExact(other: Long): Long {
    if(other<0L) throw ImplementationError("Long addition")
    val result = this + other
    if (result < this) throw Asn1Exception("ASN.1 length overflow: $this + $other")
    return result
}

/**
 * Narrows this [Long] (e.g. an ASN.1 [contentLength][Asn1Element.contentLengthLong]) to an [Int], throwing
 * [Asn1Exception] if it does not fit in `0..Int.MAX_VALUE`. Convenience for call sites that need an `Int`
 * (array sizing/indexing) but hold a [Long] length.
 */
@Suppress("NOTHING_TO_INLINE")
inline fun Long.toIntChecked(what: String = "value"): Int {
    if (this < 0 || this > Int.MAX_VALUE.toLong()) throw Asn1Exception("$what ($this) exceeds Int.MAX_VALUE")
    return toInt()
}

@Throws(IllegalArgumentException::class)
internal fun Sink.encodeLength(len: Long): Int {
    if(len<0) throw ImplementationError("Negative number of bytes to encode: $len")
    return when {
        (len < 0x80) -> writeByte(len.toByte()).run { 1 } /* short form */
        else -> { /* long form */
            val lengthLength = (Long.SIZE_BITS - len.countLeadingZeroBits() + Byte.SIZE_BITS - 1) / Byte.SIZE_BITS
            check(lengthLength < 0x80)
            writeByte((lengthLength or 0x80).toByte())
            (lengthLength - 1).downTo(0).forEach { octet ->
                writeByte((len ushr (octet * Byte.SIZE_BITS)).toByte())
            }
            1 + lengthLength
        }
    }
}
