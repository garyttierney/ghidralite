package io.github.garyttierney.ghidralite.ui.root

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.ui.main.components.Onboarding
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.util.fromRGBAHexStringOrNull
import org.jetbrains.jewel.window.DecoratedWindowScope
import org.jetbrains.jewel.window.TitleBar
import org.jetbrains.jewel.window.newFullscreenControls

@OptIn(ExperimentalFoundationApi::class, ExperimentalComposeUiApi::class)
@Composable
fun DecoratedWindowScope.TitleBarView(searchBarFocusRequester: FocusRequester) {
    var isDialogOpen by remember { mutableStateOf(false) }

    TitleBar(
        Modifier.newFullscreenControls(),
        gradientStartColor = Color.fromRGBAHexStringOrNull("#682f26") ?: Color.Unspecified
    ) {
        Row(Modifier.align(Alignment.Start).padding(start = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Ghidralite")
        }

        Text(title)
    }

}

@Composable
fun DecoratedWindowScope.GhidraliteRoot(searchBarFocusRequester: FocusRequester) {
    TitleBarView(searchBarFocusRequester)

    var workspace by remember { mutableStateOf<Workspace?>(null) }

    when (workspace) {
        null -> Onboarding(onOnboardingComplete = { workspace = it })
        else -> WorkspaceView(workspace!!)

    }
}