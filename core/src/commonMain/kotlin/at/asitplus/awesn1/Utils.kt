package at.asitplus.awesn1

infix fun <T : Any> T?.orLazy(block: () -> T) =
    if (this != null) lazyOf(this) else lazy(block)
