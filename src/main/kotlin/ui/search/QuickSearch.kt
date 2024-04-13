package io.github.garyttierney.ghidralite.ui.search

import androidx.compose.foundation.background
import androidx.compose.foundation.focusGroup
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.framework.search.SearchResult
import kotlinx.coroutines.launch
import org.jetbrains.jewel.foundation.lazy.*
import org.jetbrains.jewel.foundation.lazy.tree.DefaultSelectableLazyColumnKeyActions
import org.jetbrains.jewel.foundation.lazy.tree.KeyActions
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.Outline
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette
import org.jetbrains.jewel.ui.theme.menuStyle

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
    val itemKeys by derivedStateOf { items.map { SelectableLazyListKey.Selectable(it.element.key) }.toList() }

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
    val scope = rememberCoroutineScope()

    Box {
        SelectableLazyColumn(
            contentPadding = PaddingValues(2.dp),
            selectionMode = SelectionMode.Single,
            state = state,
            modifier = listTheme.then(Modifier.focusable()),
            onSelectedIndexesChanged = {
                val first = it.firstOrNull()
                first?.let {
                    scope.launch {
                        state.scrollToItem(it)
                    }
                }
            }
        ) {
            items.forEach {
                item(key = it.element.key) {
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
        item.element.icon()

        val matchingRangeAnnotations = item.fragments.map { range ->
            AnnotatedString.Range(
                SpanStyle(background = JewelTheme.colorPalette.yellow(3)),
                range.startOffset,
                range.startOffset + range.length
            )
        }

        val annotatedLabel = buildAnnotatedString {
            append(AnnotatedString(text = item.element.label, spanStyles = matchingRangeAnnotations))
            val parent = item.element.parent

            if (parent != null) {
                append(" ")
                pushStyle(SpanStyle(color = JewelTheme.globalColors.infoContent, fontWeight = FontWeight.Light))
                append(parent.fullyQualified())
            }
        }

        Text(
            annotatedLabel,
            maxLines = 1,
            modifier = Modifier.weight(1f, false),
            overflow = TextOverflow.Ellipsis
        )
    }
}
