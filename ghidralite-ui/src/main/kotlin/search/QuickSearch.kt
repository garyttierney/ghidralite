package search

//import io.github.garyttierney.ghidralite.LocalWindowPosition
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusProperties
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
import androidx.compose.ui.window.WindowPosition
import io.github.garyttierney.ghidralite.core.db.SymbolRecord
import io.github.garyttierney.ghidralite.core.search.SearchResult
import kotlinx.coroutines.launch
import org.jetbrains.jewel.foundation.lazy.*
import org.jetbrains.jewel.foundation.lazy.tree.DefaultSelectableLazyColumnKeyActions
import org.jetbrains.jewel.foundation.lazy.tree.KeyActions
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.Outline
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette
import org.jetbrains.jewel.ui.theme.menuStyle

val LocalWindowPosition = compositionLocalOf<WindowPosition> { WindowPosition(Alignment.Center) }

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun QuickSearch(
    items: List<SearchResult>,
    query: String,
    modifier: Modifier = Modifier,
    onQueryChanged: (String) -> Unit,
    onResultSelected: (SearchResult) -> Unit,
    focusRequester: FocusRequester = FocusRequester(),
    listActions: KeyActions = remember { DefaultSelectableLazyColumnKeyActions(DefaultSelectableColumnKeybindings) },
    itemPreview: @Composable (SearchResult) -> Unit = {}
) {
    val itemListState = rememberSelectableLazyListState()
    val itemKeys by derivedStateOf { items.map { SelectableLazyListKey.Selectable(it.element.key) }.toList() }
    val itemSelected by derivedStateOf { items.find { it.element.key == itemListState.selectedKeys.firstOrNull() } }
    val scope = rememberCoroutineScope()

    val handleListAction = { event: KeyEvent ->
        val itemListHandler = listActions.handleOnKeyEvent(event, itemKeys, itemListState, SelectionMode.Single)
        val handled = event.itemListHandler()

        if (!handled) {
            focusRequester.requestFocus()
        }

        handled
    }

    val bgModifier = modifier.then(Modifier.onPreviewKeyEvent(handleListAction))

    Column(modifier = bgModifier) {
        QuickSearchInput(
            query = query,
            focusRequester = focusRequester,
            onQueryChanged = {
                scope.launch {
                    itemListState.scrollToItem(0, animateScroll = true)
                    itemListState.lastActiveItemIndex = -1
                }

                onQueryChanged(it)
            }
        )

        QuickSearchResultList(
            items = items,
            state = itemListState,
            onItemSelected = onResultSelected,
        )
    }

    itemSelected?.let {
        itemPreview(it)
    }
}

@Composable
fun QuickSearchInput(
    query: String, onQueryChanged: (String) -> Unit,
    focusRequester: FocusRequester = remember { FocusRequester() }
) {
    TextField(
        query,
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.None),
        undecorated = true,
        outline = Outline.None,
        onValueChange = { onQueryChanged(it) },
        modifier = Modifier.fillMaxWidth().focusRequester(focusRequester),
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
            modifier = listTheme.focusProperties { canFocus = false },
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
            resource = item.element.icon,
            iconClass = SymbolRecord::class.java,
            contentDescription = item.element.label,
        )

        val matchingRangeBackground = JewelTheme.colorPalette.yellow(3)
        val matchingRangeAnnotations = item.fragments()
            .map { range ->
                AnnotatedString.Range(
                    SpanStyle(background = matchingRangeBackground),
                    range.first,
                    range.last
                )
            }
            .toList()

        val annotatedLabel = buildAnnotatedString {
            append(AnnotatedString(text = item.element.label, spanStyles = matchingRangeAnnotations))
            val namespace = item.element.namespace

            if (namespace.isNotBlank()) {
                append(" ")
                pushStyle(SpanStyle(color = JewelTheme.globalColors.infoContent, fontWeight = FontWeight.Light))
                append(namespace)
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
