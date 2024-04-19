package io.github.garyttierney.ghidralite.standalone.ui.startup

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.ApplicationScope
import androidx.compose.ui.window.Window
import io.github.garyttierney.ghidralite.standalone.ui.viewModel
import org.jetbrains.jewel.foundation.lazy.SelectableLazyColumn
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.Orientation
import org.jetbrains.jewel.ui.component.*

@Composable
fun ApplicationScope.StartupScreen(viewModel: StartupViewModel = viewModel()) {
    Window(title = "Ghidralite Launcher", onCloseRequest = { exitApplication() }) {
        Row(
            modifier = Modifier.fillMaxSize().background(JewelTheme.globalColors.paneBackground).padding(24.dp)
        ) {
            SelectableLazyColumn(modifier = Modifier.weight(0.25f)) {
                items(20, key = { it }) {
                    Text("Menu Item")
                }
            }

            Divider(orientation = Orientation.Vertical)

            Column(modifier = Modifier.weight(1.0f)) {
                Row(horizontalArrangement = Arrangement.spacedBy(5.dp, Alignment.End)) {
                    DefaultButton(onClick = {}) {
                        Text("New Project")
                    }
                    DefaultButton(onClick = {}) {
                        Text("Open")
                    }
                }
            }
            Divider(orientation = Orientation.Vertical)

        }

    }
}