package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.titleBar

import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import ghidra.framework.model.DomainFile
import io.github.garyttierney.ghidralite.standalone.ui.components.select.SelectDropdown
import io.github.garyttierney.ghidralite.standalone.ui.components.select.rememberSelectionModel
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteIcons
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette
import org.jetbrains.jewel.window.DecoratedWindowScope
import org.jetbrains.jewel.window.TitleBar
import org.jetbrains.jewel.window.newFullscreenControls

@Composable
fun DecoratedWindowScope.WorkspaceTitleBar(
    programs: List<DomainFile>,
    selectedProgram: DomainFile?,
    onProgramSelected: (DomainFile) -> Unit
) {
    val programsModel = rememberSelectionModel(programs)

    TitleBar(
        modifier = Modifier.newFullscreenControls().fillMaxWidth(),
        gradientStartColor = JewelTheme.colorPalette.red(3)
    ) {
        Row(
            modifier = Modifier.align(Alignment.Start).padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = {}) {
                GhidraliteIcons.General.WindowMenu(Modifier.size(20.dp))
            }

            SelectDropdown(
                model = programsModel,
                selectedItem = selectedProgram,
                onItemSelected = onProgramSelected,
            ) {
                Text(it.name)
            }
        }

        Row(modifier = Modifier.align(Alignment.CenterHorizontally)) {
            TextField(
                value = "",
                onValueChange = {},
                modifier = Modifier.width(300.dp),
                placeholder = { Text("Press Ctrl-P to begin searching ") })
        }
    }
}