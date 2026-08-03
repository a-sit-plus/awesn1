package at.asitplus.awesn1

@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.InlineOnly
public inline fun CharSequence.indexOfFirst(startIndex: Int, predicate: (Char) -> Boolean): Int {
    for (index in startIndex until length) {
        if (predicate(this[index])) {
            return index
        }
    }
    return -1
}