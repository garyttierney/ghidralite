package io.github.garyttierney.ghidralite.standalone.app.ui.views.startup

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import ghidra.framework.model.Project
import io.github.garyttierney.ghidralite.standalone.app.ui.GhidraliteApplicationScreen
import io.github.garyttierney.ghidralite.standalone.app.ui.LocalApplicationScreenHolder
import io.github.garyttierney.ghidralite.standalone.app.ui.views.startup.projectSelector.ProjectSelector
import io.github.garyttierney.ghidralite.standalone.ui.components.select.SelectList
import io.github.garyttierney.ghidralite.standalone.ui.components.select.rememberSelectionModel
import io.github.garyttierney.ghidralite.standalone.ui.components.surface.Panel
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteIcons
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteTypography
import io.github.garyttierney.ghidralite.standalone.ui.viewModel
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette
import org.jetbrains.jewel.window.DecoratedWindowScope
import org.jetbrains.jewel.window.TitleBar

class ProjectScreen(val project: Project) : GhidraliteApplicationScreen() {
    init {
        preferredSize = DpSize(360.dp, 480.dp)
    }

    @Composable
    override fun DecoratedWindowScope.content() {
        val viewModel = viewModel<StartupViewModel>()

        TitleBar { Text("Welcome to Ghidralite") }

        Panel {
            Row {
                Column(modifier = Modifier.requiredWidth(240.dp).padding(24.dp)) {
                    StartupInformation()
                    StartupOptionList(onOptionChanged = { viewModel.selectedOption = it })
                }

                Column(
                    modifier = Modifier.weight(1.0f).requiredWidthIn(min = 300.dp)
                        .fillMaxSize()
                        .background(JewelTheme.colorPalette.grey(1))
                        .padding(24.dp)
                ) {
                    StartupOptionDetail(selectedOption = viewModel.selectedOption)
                }
            }
        }
    }
}


@Composable
fun DecoratedWindowScope.StartupView() {

}

@Composable
fun ColumnScope.StartupOptionList(onOptionChanged: (StartupScreenOption) -> Unit) {
    val optionsModel = rememberSelectionModel(
        items = listOf(StartupScreenOption.ProjectSelector),
    )

    SelectList(listModel = optionsModel, onItemSelected = onOptionChanged) {
        Text(it.toString())
    }

    Spacer(modifier = Modifier.weight(1f))

    IconButton(onClick = {}) {
        GhidraliteIcons.General.Settings(Modifier.size(20.dp))
    }
}

@Composable
fun StartupOptionDetail(selectedOption: StartupScreenOption) {
    val screenHolder = LocalApplicationScreenHolder.current

    fun onScreenSelected(screen: GhidraliteApplicationScreen) {
        screenHolder.replaceWith(screen)
    }

    when (selectedOption) {
        StartupScreenOption.ProjectSelector -> ProjectSelector(
            onWorkspaceOpened = {
                onScreenSelected(GhidraliteApplicationScreen.WorkspaceScreen(it))
            }
        )
    }
}

@Composable
fun StartupInformation() {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.padding(vertical = 16.dp)
    ) {
        GhidraliteIcons.Ghidralite(Modifier.size(32.dp))

        Column {
            Text("Ghidralite")
            BasicText("0.4.0 (Ghidra 11.0.3)", style = GhidraliteTypography.hint())
        }
    }
}