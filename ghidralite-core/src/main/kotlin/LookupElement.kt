package io.github.garyttierney.ghidralite.core

interface LookupElement {
    val key: Any
    val label: String
    val parent: LookupElement?
    val icon: String

    fun ancestors(): Sequence<LookupElement> = sequence {
        val p = parent
        if (p != null) {
            yield(p)
            yieldAll(p.ancestors())
        }
    }

    val namespace: String
    val fullyQualifiedName: String
        get() = if (namespace.isEmpty()) {
            label
        } else {
            "$namespace::$label"
        }

}
