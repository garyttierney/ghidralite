package io.github.garyttierney.ghidralite.standalone.ui.windows.startup

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.ApplicationScope
import androidx.compose.ui.window.WindowPosition
import androidx.compose.ui.window.rememberWindowState
import ghidra.framework.model.Project
import io.github.garyttierney.ghidralite.standalone.ui.components.list.SelectableList
import io.github.garyttierney.ghidralite.standalone.ui.components.list.rememberListModel
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteIcons
import io.github.garyttierney.ghidralite.standalone.ui.viewModel
import io.github.garyttierney.ghidralite.standalone.ui.windows.startup.projectSelector.ProjectSelector
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette
import org.jetbrains.jewel.window.DecoratedWindow
import org.jetbrains.jewel.window.TitleBar

@Composable
fun ApplicationScope.StartupWindow(viewModel: StartupViewModel = viewModel(), onProjectOpened: (Project) -> Unit) {
    val optionsModel = rememberListModel(
        items = listOf(StartupScreenOption.ProjectSelector),
        labelSelector = { it.toString() },
    )

    DecoratedWindow(
        title = "Ghidralite Launcher",
        onCloseRequest = { exitApplication() },
        resizable = false,
        state = rememberWindowState(position = WindowPosition.Aligned(Alignment.Center)),
    ) {
        TitleBar {
            Text("Ghidralite")
        }

        Row(
            modifier = Modifier
                .fillMaxSize()
                .background(JewelTheme.globalColors.paneBackground)
        ) {
            Column(modifier = Modifier.requiredWidth(240.dp).padding(24.dp)) {
                SelectableList(selectableListModel = optionsModel, onItemSelected = {}) {
                    Text(it.toString())
                }

                Spacer(modifier = Modifier.weight(1f))

                IconButton(onClick = {}) {
                    GhidraliteIcons.General.Settings(Modifier.size(20.dp))
                }
            }

            Column(
                modifier = Modifier.weight(1.0f).requiredWidthIn(min = 300.dp)
                    .fillMaxSize()
                    .background(JewelTheme.colorPalette.grey(1))
                    .padding(24.dp)
            ) {
                when (viewModel.selectedOption) {
                    StartupScreenOption.ProjectSelector -> ProjectSelector(onProjectSelected = onProjectOpened)
                }
            }
        }
    }
}