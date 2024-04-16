package io.github.garyttierney.ghidralite.ui.root

import androidx.compose.foundation.background
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.SwingPanel
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jetbrains.compose.splitpane.ExperimentalSplitPaneApi
import org.jetbrains.compose.splitpane.rememberSplitPaneState
import org.jetbrains.jewel.foundation.theme.JewelTheme
import java.awt.BorderLayout
import javax.swing.JPanel

//
//@OptIn(ExperimentalSplitPaneApi::class)
//@Composable
//fun WorkspaceView(model: Workspace) = key(model) {
//    val state = rememberSplitPaneState(0.25f)
//    var workspaceSearchOpen by remember { mutableStateOf(false) }
//    var searchQuery by remember { mutableStateOf("") }
//    val searchInputFocus = remember { FocusRequester() }
//    val searchResults = remember { mutableStateListOf<SearchResult>() }
//
//    val searchScope = rememberCoroutineScope()
//
//
//    val keyboardHandler = { event: KeyEvent ->
//        var handled = true
//        val key = event.key
//
//        when {
//            key == Key.Escape -> workspaceSearchOpen = false
//            key == Key.P && event.isCtrlPressed -> {
//                workspaceSearchOpen = true
//            }
//
//            else -> handled = false
//        }
//
//        handled
//    }
//
//    Box(
//        modifier = Modifier.onPreviewKeyEvent(keyboardHandler)
//            .background(JewelTheme.globalColors.paneBackground)
//            .windowInsetsPadding(WindowInsets.safeDrawing)
//            .focusable(true)
//    ) {
//        QuickSearch(
//            items = searchResults,
//            query = searchQuery,
//            itemPreview = { item ->
//                Box(modifier = Modifier.background(Color.Red)) {
//                    SwingPanel(
//                        modifier = Modifier.fillMaxSize().background(Color.Red),
//                        factory = {
//                            val panel = JPanel(BorderLayout())
//                            panel.add(model.listing, BorderLayout.CENTER)
//                            panel
//                        },
//                        update = {
//                            val sym = model.program.symbolTable.getSymbol(item.element.key as Long)
//                            model.listing.goTo(sym.address)
//                        }
//                    )
//                }
//            },
//            onQueryChanged = {
//                searchQuery = it
//                searchResults.clear()
//
//                searchScope.launch {
//                    withContext(Dispatchers.IO) {
//                        model.searcher.query(searchQuery, onDataAvailable = {
//                            searchResults.clear()
//                            searchResults.addAll(it)
//                        })
//                    }
//                }
//            },
//            onResultSelected = {},
//            focusRequester = searchInputFocus,
//        )
//    }
//}
