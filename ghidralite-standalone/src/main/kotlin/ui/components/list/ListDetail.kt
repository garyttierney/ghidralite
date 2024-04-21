package io.github.garyttierney.ghidralite.standalone.ui.components.list

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.*
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsDraggedAsState
import androidx.compose.foundation.interaction.collectIsHoveredAsState
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.layout.layout
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach
import kotlin.math.max
import kotlin.math.roundToInt

/**
 * A higher-order component displaying an opinionated list-detail format.
 *
 * The [list] slot is the primary content, and is in a parent relationship with the content
 * displayed in [detail].
 *
 * This relationship implies that different detail screens may be swapped out for each other, and
 * should be distinguished by passing a [detailKey] to control when a different detail is being
 * shown (to reset instance state.
 *
 * When there is enough space to display both list and detail, pass `true` to [showListAndDetail]
 * to show both the list and the detail at the same time. This content is displayed in a [TwoPane].
 *
 * When there is not enough space to display both list and detail, which slot is displayed is based
 * on [isDetailOpen]. Internally, this state is changed in an opinionated way via [setIsDetailOpen].
 * For instance, when showing just the detail screen, a back button press will call
 * [setIsDetailOpen] passing `false`.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ListDetail(
    isDetailOpen: Boolean,
    setIsDetailOpen: (Boolean) -> Unit,
    showListAndDetail: Boolean,
    detailKey: Any?,
    list: @Composable (isDetailVisible: Boolean) -> Unit,
    detail: @Composable (isListVisible: Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val currentIsDetailOpen by rememberUpdatedState(isDetailOpen)
    val currentShowListAndDetail by rememberUpdatedState(showListAndDetail)
    val currentDetailKey by rememberUpdatedState(detailKey)

    // Determine whether to show the list and/or the detail.
    // This is a function of current app state, and the width size class.
    val showList by remember {
        derivedStateOf {
            currentShowListAndDetail || !currentIsDetailOpen
        }
    }
    val showDetail by remember {
        derivedStateOf {
            currentShowListAndDetail || currentIsDetailOpen
        }
    }
    // Validity check: we should always be showing something
    check(showList || showDetail)

    val listSaveableStateHolder = rememberSaveableStateHolder()
    val detailSaveableStateHolder = rememberSaveableStateHolder()

    val start = remember {
        movableContentOf {
            // Set up a SaveableStateProvider so the list state will be preserved even while it
            // is hidden if the detail is showing instead.
            listSaveableStateHolder.SaveableStateProvider(0) {
                Box() {
                    list(showDetail)
                }
            }
        }
    }

    val end = remember {
        movableContentOf {
            // Set up a SaveableStateProvider against the selected word index to save detail
            // state while switching between details.
            // If this behavior isn't desired, this can be replaced with a key on the
            // selectedWordIndex.
            detailSaveableStateHolder.SaveableStateProvider(currentDetailKey ?: "null") {
                Box(
                ) {
                    detail(showList)
                }
            }
        }
    }

    val density = LocalDensity.current
    val anchoredDraggableState = rememberSaveable(
        saver = AnchoredDraggableState.Saver(
            animationSpec = spring(),
            positionalThreshold = { distance: Float -> distance * 0.5f },
            velocityThreshold = { with(density) { 400.dp.toPx() } },
        )
    ) {
        AnchoredDraggableState(
            initialValue = ExpandablePaneState.ListAndDetail,
            animationSpec = spring(),
            positionalThreshold = { distance: Float -> distance * 0.5f },
            velocityThreshold = { with(density) { 400.dp.toPx() } },
        )
    }

    // Sync the `isDetailOpen` as a side-effect to the expandable pane state.
    LaunchedEffect(isDetailOpen) {
        if (isDetailOpen) {
            when (anchoredDraggableState.currentValue) {
                ExpandablePaneState.ListOnly -> {
                    anchoredDraggableState.animateTo(ExpandablePaneState.DetailOnly)
                }

                ExpandablePaneState.ListAndDetail,
                ExpandablePaneState.DetailOnly
                -> Unit
            }
        } else {
            when (anchoredDraggableState.currentValue) {
                ExpandablePaneState.ListOnly,
                ExpandablePaneState.ListAndDetail -> Unit

                ExpandablePaneState.DetailOnly -> {
                    anchoredDraggableState.animateTo(ExpandablePaneState.ListOnly)
                }
            }
        }
    }

    // Update the `isDetailOpen` boolean as a side-effect of the expandable pane reaching a specific value.
    // We only do this if both the list and detail are capable of being shown, as
    if (showListAndDetail) {
        LaunchedEffect(anchoredDraggableState) {
            snapshotFlow { anchoredDraggableState.currentValue }
                .onEach {
                    when (anchoredDraggableState.currentValue) {
                        ExpandablePaneState.ListOnly -> setIsDetailOpen(false)
                        ExpandablePaneState.ListAndDetail -> setIsDetailOpen(true)
                        ExpandablePaneState.DetailOnly -> setIsDetailOpen(true)
                    }
                }
                .collect()
        }
    }

    val minListPaneWidth = 300.dp
    val minDetailPaneWidth = 300.dp


    if (showList && showDetail) {
        Row {
            Box(
                Modifier
                    .clipToBounds()
                    .layout { measurable, constraints ->
                        val width = max(minListPaneWidth.roundToPx(), constraints.maxWidth)
                        val placeable = measurable.measure(
                            constraints.copy(
                                minWidth = minListPaneWidth.roundToPx(),
                                maxWidth = width
                            )
                        )
                        layout(constraints.maxWidth, placeable.height) {
                            placeable.placeRelative(
                                x = 0,
                                y = 0
                            )
                        }
                    }
            ) {
                start()
            }

            Box(
                Modifier
                    .clipToBounds()
                    .layout { measurable, constraints ->
                        val width = max(minDetailPaneWidth.roundToPx(), constraints.maxWidth)
                        val placeable = measurable.measure(
                            constraints.copy(
                                minWidth = minDetailPaneWidth.roundToPx(),
                                maxWidth = width
                            )
                        )
                        layout(constraints.maxWidth, placeable.height) {
                            placeable.placeRelative(
                                x = constraints.maxWidth - max(constraints.maxWidth, placeable.width),
                                y = 0
                            )
                        }
                    }
            ) {
                end()
            }
        }
    } else if (showList) {
        start()
    } else {
        end()
    }
}

enum class ExpandablePaneState {
    ListOnly, ListAndDetail, DetailOnly
}