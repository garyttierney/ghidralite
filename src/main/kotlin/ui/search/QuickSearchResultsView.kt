package io.github.garyttierney.ghidralite.ui.search

import androidx.compose.desktop.ui.tooling.preview.Preview
import androidx.compose.foundation.*
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onKeyEvent
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.framework.search.SearchResult
import io.github.garyttierney.ghidralite.ui.internal.PreviewComponent
import kotlinx.coroutines.launch
import org.jetbrains.jewel.foundation.lazy.SelectableLazyColumn
import org.jetbrains.jewel.foundation.lazy.SelectableLazyListState
import org.jetbrains.jewel.foundation.lazy.SelectionMode
import org.jetbrains.jewel.foundation.lazy.rememberSelectableLazyListState
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.Outline
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.component.VerticalScrollbar
import org.jetbrains.jewel.ui.theme.colorPalette
import org.jetbrains.jewel.ui.theme.menuStyle

@Composable
fun QuickSearch(
    items: List<SearchResult>,
    query: String,
    onQueryChanged: (String) -> Unit,
    onResultSelected: (SearchResult) -> Unit,
    focusRequester: FocusRequester = FocusRequester()
) {
    val borderColor = JewelTheme.globalColors.borders.normal
    val bgColor = JewelTheme.menuStyle.colors.background

    val interactionSource = remember { MutableInteractionSource() }
    val state = rememberSelectableLazyListState()
    val scope = rememberCoroutineScope()

    Column(modifier = Modifier.background(bgColor).focusGroup().border(1.dp, borderColor)) {
        TextField(
            query,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
            undecorated = true,
            outline = Outline.None,
            onValueChange = onQueryChanged,
            modifier = Modifier.fillMaxWidth()
                .focusRequester(focusRequester)
                .focusable(true)
                ,
            placeholder = { Text("Type a query to begin searching") },
            interactionSource = interactionSource,
        )

        QuickSearchResultList(items = items, onItemSelected = onResultSelected, interactionSource = interactionSource)
    }
}

@Composable
fun QuickSearchResultList(
    items: List<SearchResult>,
    onItemSelected: (SearchResult) -> Unit,
    interactionSource: MutableInteractionSource = remember { MutableInteractionSource() },
    state: SelectableLazyListState = rememberSelectableLazyListState()
) {
    Box {
        SelectableLazyColumn(
            contentPadding = PaddingValues(2.dp),
            selectionMode = SelectionMode.Single,
            interactionSource = interactionSource,
            state = state,
            modifier = Modifier.fillMaxSize()
                .background(JewelTheme.menuStyle.colors.background)
                .focusable(interactionSource = interactionSource)
                .indication(interactionSource = interactionSource, LocalIndication.current),
        ) {


            items.forEach {
                item(key = it.uniqueKey) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.Bottom,
                        modifier = Modifier.fillMaxWidth().padding(4.dp)
                            .then(
                                when {
                                    isSelected -> Modifier.background(JewelTheme.menuStyle.colors.itemColors.backgroundFocused)
                                    !isSelected -> Modifier.background(JewelTheme.menuStyle.colors.itemColors.background)
                                    else -> Modifier
                                },
                            )
                    ) {
                        Icon(
                            "/nodes/method.svg",
                            contentDescription = "Test",
                            iconClass = SearchResult::class.java,
                            modifier = Modifier.size(16.dp)
                        )

                        Text(
                            AnnotatedString(
                                text = it.name,
                                spanStyles = it.fragments.map { range ->
                                    AnnotatedString.Range(
                                        SpanStyle(background = JewelTheme.colorPalette.yellow(3)),
                                        range.startOffset,
                                        range.startOffset + range.length
                                    )
                                }
                            ),
                            maxLines = 1,
                            modifier = Modifier.weight(1f, false),
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }

        }

        LaunchedEffect(items) {
            state.lastActiveItemIndex = 0
        }

        VerticalScrollbar(
            rememberScrollbarAdapter(state.lazyListState),
            modifier = Modifier.align(Alignment.CenterEnd),
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

    QuickSearch(
        items = items.toList(),
        query = "Search query",
        onQueryChanged = {},
        onResultSelected = {})
}