package io.github.garyttierney.ghidralite.core.search

import com.intellij.psi.codeStyle.NameUtil
import io.github.garyttierney.ghidralite.core.db.SymbolLookupDetails
import io.github.garyttierney.ghidralite.core.index.Index
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.channels.trySendBlocking
import kotlinx.coroutines.flow.*
import java.util.*
import kotlin.time.Duration.Companion.milliseconds

class Searcher(private val index: Index<Long, SymbolLookupDetails>) {
    @OptIn(FlowPreview::class)
    suspend fun query(
        query: String,
        onDataAvailable: (List<SearchResult>) -> Unit
    ) {
        val queueCapacity = 50
        val isFqnQuery = query.contains("::")
        val pattern = if (isFqnQuery) "*$query" else query

        val labelMatcher = NameUtil.buildMatcher(pattern)
            .withCaseSensitivity(NameUtil.MatchingCaseSensitivity.NONE)
            .withSeparators("_")
            .preferringStartMatches()
            .typoTolerant()
            .build()

        val resultFlow = channelFlow {
            index.process {
                val value = it.value
                val label = if (isFqnQuery) value.fullyQualifiedName else value.label
                val labelOffset = label.length - value.label.length
                val fragments = labelMatcher.matchingFragments(label)
                val score = labelMatcher.matchingDegree(label, false, fragments)

                if (score > 0) {
                    trySendBlocking(SearchResult(value, score, fragments, labelOffset))
                }
            }
        }

        resultFlow
            .scan(PriorityQueue(naturalOrder<SearchResult>())) { queue, item ->
                val newQueue = PriorityQueue(queue)
                val beatsWorst = newQueue.size == queueCapacity && newQueue.peek().score < item.score
                val adding = beatsWorst || newQueue.size < queueCapacity

                if (adding) {
                    newQueue.add(item)
                }

                newQueue
            }
            .conflate()
            .debounce(100.milliseconds)
            .collectLatest {
                onDataAvailable(it.sortedDescending())
            }
    }
}

