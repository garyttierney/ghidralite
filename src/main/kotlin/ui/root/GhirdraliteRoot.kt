package io.github.garyttierney.ghidralite.ui.root

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.graphics.*
import androidx.compose.ui.unit.*
import io.github.garyttierney.ghidralite.ui.main.components.Onboarding
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.util.fromRGBAHexStringOrNull
import org.jetbrains.jewel.window.DecoratedWindowScope
import org.jetbrains.jewel.window.TitleBar
import org.jetbrains.jewel.window.newFullscreenControls

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun DecoratedWindowScope.TitleBarView() {
    TitleBar(
        Modifier.newFullscreenControls(),
        gradientStartColor = Color.fromRGBAHexStringOrNull("#682f26") ?: Color.Unspecified
    ) {
        Row(Modifier.align(Alignment.Start).padding(start = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Ghidralite")
        }

        Text(title)
        TextField(
            value = "",
            onValueChange = { },
            modifier = Modifier.align(Alignment.CenterHorizontally).fillMaxWidth(0.6f).focusable(),
            placeholder = { Text("Press Ctrl-P to begin searching") }
        )
    }
}

@Composable
fun DecoratedWindowScope.GhidraliteRoot() {
    TitleBarView()

    var workspace by remember { mutableStateOf<Workspace?>(null) }

    Box(
        Modifier.fillMaxSize()
            .background(JewelTheme.globalColors.paneBackground)
            .windowInsetsPadding(WindowInsets.safeDrawing)
    ) {
        when (workspace) {
            null -> Onboarding(onOnboardingComplete = { workspace = it })
            else -> WorkspaceView(workspace!!)
        }
    }
}