package io.github.garyttierney.ghidralite.core.search

import com.intellij.openapi.util.TextRange
import com.intellij.util.containers.FList
import io.github.garyttierney.ghidralite.core.LookupElement

data class SearchResult(
    val element: LookupElement,
    val score: Int,
    private val fragments: FList<TextRange>,
    private val labelOffset: Int
) : Comparable<SearchResult> {
    override fun compareTo(other: SearchResult): Int = score.compareTo(other.score)

    fun fragments() = fragments.asSequence()
        .filter { it.startOffset >= labelOffset }
        .map { IntRange(it.startOffset - labelOffset, it.endOffset - labelOffset) }

}