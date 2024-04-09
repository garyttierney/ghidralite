package io.github.garyttierney.ghidralite.ui.root

import androidx.compose.foundation.*
import androidx.compose.foundation.interaction.*
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.awt.*
import androidx.compose.ui.unit.*
import org.jetbrains.compose.splitpane.ExperimentalSplitPaneApi
import org.jetbrains.compose.splitpane.HorizontalSplitPane
import org.jetbrains.compose.splitpane.rememberSplitPaneState
import org.jetbrains.jewel.ui.component.*


@OptIn(ExperimentalSplitPaneApi::class)
@Composable
fun WorkspaceView(model: Workspace) = key(model) {
    val state = rememberSplitPaneState(0.25f)
    val interactionSource = remember { MutableInteractionSource() }

    HorizontalSplitPane(splitPaneState = state) {
        first(minSize = 8.dp) {
            Text("Hello")
        }

        second {
            SwingPanel(factory = { model.listing }, modifier = Modifier.fillMaxSize().hoverable(interactionSource))
        }
    }
}
