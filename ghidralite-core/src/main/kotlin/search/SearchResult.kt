package io.github.garyttierney.ghidralite.core.search

import io.github.garyttierney.ghidralite.core.LookupElement

data class SearchResult(
    val element: LookupElement,
    val score: Int,
    val fragments: List<IntRange>
) : Comparable<SearchResult> {
    override fun compareTo(other: SearchResult): Int = score.compareTo(other.score)
}