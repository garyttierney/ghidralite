package io.github.garyttierney.ghidralite.standalone.app.ui.views.projectSelector

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.standalone.app.ui.GhidraliteApplicationScreen
import io.github.garyttierney.ghidralite.standalone.app.ui.LocalApplicationScreenHolder
import io.github.garyttierney.ghidralite.standalone.app.ui.views.startup.projectSelector.ProjectSelector
import io.github.garyttierney.ghidralite.standalone.ui.components.surface.Panel
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteIcons
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.window.DecoratedWindowScope
import org.jetbrains.jewel.window.TitleBar

@Composable
fun DecoratedWindowScope.ProjectSelectorView() {
    TitleBar {
        Row(
            modifier = Modifier.align(Alignment.Start).padding(horizontal = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),

        ) {
            GhidraliteIcons.Ghidralite(Modifier.align(Alignment.Start).size(16.dp))
            Text("Ghidralite", modifier = Modifier.align(Alignment.Start))
        }

    }

    val screenHolder = LocalApplicationScreenHolder.current

    Panel(modifier = Modifier.fillMaxSize()) {
        ProjectSelector(
            onWorkspaceOpened = {
                screenHolder.replaceWith(GhidraliteApplicationScreen.WorkspaceScreen(it))
            }
        )
    }
}