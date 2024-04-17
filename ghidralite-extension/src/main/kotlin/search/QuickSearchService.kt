package io.github.garyttierney.ghidralite.extension.search

import io.github.garyttierney.ghidralite.core.search.SearchResult

interface QuickSearchService {
    suspend fun search(query: String, onResultAvailable: (List<SearchResult>) -> Unit)
}