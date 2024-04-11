package io.github.garyttierney.ghidralite.ui.search

import androidx.compose.foundation.window.WindowDraggableArea
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.WindowPosition
import androidx.compose.ui.window.WindowState
import androidx.compose.ui.window.rememberWindowState
import io.github.garyttierney.ghidralite.LocalWindowPosition
import io.github.garyttierney.ghidralite.framework.search.SearchResult
import java.util.concurrent.PriorityBlockingQueue

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun QuickSearchWindow(
    visible: Boolean = true,
    state: WindowState = rememberWindowState(),
    results: List<SearchResult>,
    onResultSelected: (SearchResult) -> Unit,
    query: String = "",
    onQueryChanged: (String) -> Unit,
    onCloseRequest: () -> Unit,
    queryFocus: FocusRequester = FocusRequester()
) {
    val parentWindowSize = LocalWindowInfo.current.containerSize
    val parentWindowPosition = LocalWindowPosition.current

    val popupOffset = Alignment.Center.align(
        IntSize(300, 300),
        parentWindowSize,
        LayoutDirection.Ltr
    )

    val windowState = rememberWindowState(
        position = WindowPosition(parentWindowPosition.x + popupOffset.x.dp, parentWindowPosition.y + popupOffset.y.dp),
        width = 300.dp,
        height = 300.dp
    )

    Window(
        undecorated = true,
        alwaysOnTop = true,
        title = "Ghidralite Quick Search",
        state = windowState,
        visible = visible,
        onCloseRequest = onCloseRequest,
        onPreviewKeyEvent = {
            queryFocus.requestFocus()
            false
        },
        resizable = true,
    ) {
        WindowDraggableArea {
            QuickSearch(
                results,
                query = query,
                onQueryChanged = onQueryChanged,
                onResultSelected = onResultSelected,
                focusRequester = queryFocus
            )
        }
    }
}