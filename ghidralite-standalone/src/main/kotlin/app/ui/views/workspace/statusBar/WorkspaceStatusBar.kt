package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.statusBar

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.standalone.app.task.TaskRunner
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.statusBar.widgets.ResourceConsumption
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.statusBar.widgets.TaskProgress
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.foundation.theme.LocalContentColor
import org.jetbrains.jewel.ui.Orientation
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette

@Composable
fun WorkspaceStatusBar() {
    Divider(orientation = Orientation.Horizontal, color = JewelTheme.colorPalette.grey(1))

    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        CompositionLocalProvider(LocalContentColor provides JewelTheme.colorPalette.grey(9)) {
            Spacer(modifier = Modifier.weight(1f))


            TaskProgress()
            ResourceConsumption()
        }
    }
}