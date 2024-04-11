package io.github.garyttierney.ghidralite.ui.root

import androidx.compose.foundation.background
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.input.key.*
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.ui.search.QuickSearchWindow
import io.github.garyttierney.ghidralite.framework.search.SearchResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jetbrains.compose.splitpane.ExperimentalSplitPaneApi
import org.jetbrains.compose.splitpane.HorizontalSplitPane
import org.jetbrains.compose.splitpane.rememberSplitPaneState
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*
import java.util.concurrent.PriorityBlockingQueue


@OptIn(ExperimentalSplitPaneApi::class)
@Composable
fun WorkspaceView(model: Workspace) = key(model) {
    val state = rememberSplitPaneState(0.25f)
    var workspaceSearchOpen by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    val searchInputFocus = remember { FocusRequester() }
    val searchResults = remember { mutableStateListOf<SearchResult>() }

    val searchScope = rememberCoroutineScope()


    val keyboardHandler = { event: KeyEvent ->
        var handled = true
        val key = event.key

        when {
            key == Key.Escape -> workspaceSearchOpen = false
            key == Key.P && event.isCtrlPressed -> {
                workspaceSearchOpen = true
            }

            else -> handled = false
        }

        handled
    }

    Box(
        modifier = Modifier.onPreviewKeyEvent(keyboardHandler)
            .background(JewelTheme.globalColors.paneBackground)
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .focusable(true)
    ) {

        HorizontalSplitPane(splitPaneState = state, modifier = Modifier.onPreviewKeyEvent(keyboardHandler)) {
            first(minSize = 8.dp) {
                Text("Hello")
            }

            second {
            }
        }

        QuickSearchWindow(
            visible = workspaceSearchOpen,
            results = searchResults,
            onResultSelected = {},
            query = searchQuery,
            onQueryChanged = {
                searchQuery = it
                searchResults.clear()

                searchScope.launch {
                    withContext(Dispatchers.IO) {
                        model.searcher.query(searchQuery, onDataAvailable = {
                            searchResults.clear()
                            searchResults.addAll(it)
                        })
                    }
                }
            },
            queryFocus = searchInputFocus,
            onCloseRequest = {
                workspaceSearchOpen = false
            }
        )
    }
}
