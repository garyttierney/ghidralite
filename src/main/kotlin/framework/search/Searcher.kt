package io.github.garyttierney.ghidralite.framework.search

import com.intellij.psi.codeStyle.NameUtil
import io.github.garyttierney.ghidralite.framework.search.index.Indexes

class Searcher(val indexes: Indexes) {
    fun query(query: String): SearchResult {
        val matcher = NameUtil.buildMatcher("*$input")
            .withCaseSensitivity(NameUtil.MatchingCaseSensitivity.NONE)
            .preferringStartMatches()
            .withSeparators(".:")
            .typoTolerant()
            .build()
    }
}