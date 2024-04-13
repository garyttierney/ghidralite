package io.github.garyttierney.ghidralite.ui.search

import androidx.compose.desktop.ui.tooling.preview.Preview
import androidx.compose.foundation.background
import androidx.compose.foundation.focusGroup
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.framework.search.SearchResult
import io.github.garyttierney.ghidralite.ui.internal.PreviewComponent
import org.jetbrains.jewel.foundation.lazy.*
import org.jetbrains.jewel.foundation.lazy.tree.DefaultSelectableLazyColumnKeyActions
import org.jetbrains.jewel.foundation.lazy.tree.KeyActions
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.Outline
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette
import org.jetbrains.jewel.ui.theme.menuStyle

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun QuickSearch(
    items: List<SearchResult>,
    query: String,
    onQueryChanged: (String) -> Unit,
    onResultSelected: (SearchResult) -> Unit,
    focusRequester: FocusRequester = FocusRequester(),
    listActions: KeyActions = remember { DefaultSelectableLazyColumnKeyActions(DefaultSelectableColumnKeybindings) }
) {
    val itemListState = rememberSelectableLazyListState()
    val itemKeys by derivedStateOf { items.map { SelectableLazyListKey.Selectable(it.uniqueKey) }.toList() }

    val handleListAction = { event: KeyEvent ->
        val itemListHandler = listActions.handleOnKeyEvent(event, itemKeys, itemListState, SelectionMode.Single)

        if (event.itemListHandler()) {
            true
        } else {
            false
        }
    }

    Column(modifier = Modifier.onPreviewKeyEvent(handleListAction).focusRequester(focusRequester).focusGroup()) {
        QuickSearchInput(query = query, onQueryChanged = onQueryChanged)

        QuickSearchResultList(
            items = items,
            state = itemListState,
            onItemSelected = onResultSelected,
        )
    }
}

@Composable
fun QuickSearchInput(
    query: String, onQueryChanged: (String) -> Unit
) {
    TextField(
        query,
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
        undecorated = true,
        outline = Outline.None,
        onValueChange = { onQueryChanged(it) },
        modifier = Modifier.fillMaxWidth(),
        placeholder = { Text("Type a query to begin searching") },
    )
}

@Composable
fun QuickSearchResultList(
    items: List<SearchResult>,
    onItemSelected: (SearchResult) -> Unit,
    state: SelectableLazyListState = rememberSelectableLazyListState(),
) {
    val listTheme = Modifier.fillMaxSize().background(JewelTheme.menuStyle.colors.background)

    Box {
        SelectableLazyColumn(
            contentPadding = PaddingValues(2.dp),
            selectionMode = SelectionMode.Single,
            state = state,
            modifier = listTheme.focusable(),
        ) {
            items.forEach {
                item(key = it.uniqueKey) {
                    QuickSearchResult(item = it)
                }
            }
        }

        LaunchedEffect(items) {
            state.scrollToItem(0)
            state.lastActiveItemIndex = -1
        }

        VerticalScrollbar(
            rememberScrollbarAdapter(state.lazyListState),
            modifier = Modifier.align(Alignment.CenterEnd),
        )
    }
}


@Composable
fun SelectableLazyItemScope.QuickSearchResult(item: SearchResult) {
    val rowTheme = Modifier.fillMaxWidth().padding(4.dp).then(
        when {
            isSelected -> Modifier.background(JewelTheme.menuStyle.colors.itemColors.backgroundFocused)
            !isSelected -> Modifier.background(JewelTheme.menuStyle.colors.itemColors.background)
            else -> Modifier
        },
    )

    Row(
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.Bottom,
        modifier = rowTheme
    ) {
        Icon(
            "/nodes/method.svg",
            contentDescription = "Test",
            iconClass = SearchResult::class.java,
            modifier = Modifier.size(16.dp)
        )

        val matchingRangeAnnotations = item.fragments.map { range ->
            AnnotatedString.Range(
                SpanStyle(background = JewelTheme.colorPalette.yellow(3)),
                range.startOffset,
                range.startOffset + range.length
            )
        }

        Text(
            AnnotatedString(text = item.name, spanStyles = matchingRangeAnnotations),
            maxLines = 1,
            modifier = Modifier.weight(1f, false),
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Preview
@Composable
internal fun QuickSearchPreview() = PreviewComponent {
    val items = (0..10).map {
        SearchResult(
            "name", "subheading", "type", 1, it as Long, mutableListOf()
        )
    }

    QuickSearch(items = items.toList(), query = "Search query", onQueryChanged = {}, onResultSelected = {})
}