package io.github.garyttierney.ghidralite.standalone.app.ui.views.startup.projectSelector

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.darkrockstudios.libraries.mpfilepicker.FilePicker
import ghidra.framework.model.ProjectLocator
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.Workspace
import io.github.garyttierney.ghidralite.standalone.ui.components.Hint
import io.github.garyttierney.ghidralite.standalone.ui.components.select.SelectList
import io.github.garyttierney.ghidralite.standalone.ui.components.select.rememberSelectionModel
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteIcons
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteTypography
import io.github.garyttierney.ghidralite.standalone.ui.viewModel
import io.github.garyttierney.ghidralite.ui.components.PlaceholderIcon
import kotlinx.coroutines.launch
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.Orientation
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette
import java.io.File

@Composable
fun ProjectSelector(viewModel: ProjectSelectorViewModel = viewModel(), onWorkspaceOpened: (Workspace) -> Unit) {
    val scope = rememberCoroutineScope()

    fun onProjectLocatorSelected(locator: ProjectLocator) = scope.launch {
        onWorkspaceOpened(viewModel.loadWorkspace(locator))
    }

    ProjectSelectorHeader(
        filter = viewModel.projectFilter,
        onFilterChanged = { newFilter -> viewModel.projectFilter = newFilter },
        onProjectSelectorOpened = { viewModel.openProjectFileSelector = true }
    )

    FilePicker(show = viewModel.openProjectFileSelector, fileExtensions = listOf("gpr")) {
        viewModel.openProjectFileSelector = false

        it?.let { path ->
            val file = path.platformFile as File
            val locator = ProjectLocator(file.parent, file.name)

            onProjectLocatorSelected(locator)
        }
    }

    Divider(
        orientation = Orientation.Horizontal,
        color = JewelTheme.colorPalette.grey(4),
        thickness = 1.dp,
        modifier = Modifier.padding(vertical = 8.dp)
    )

    val projectListModel = rememberSelectionModel(viewModel.recentProjects)

    SelectList(
        listModel = projectListModel,
        modifier = Modifier.fillMaxSize(),
        onItemSelected = ::onProjectLocatorSelected,
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            PlaceholderIcon(it.name)
            Column(modifier = Modifier.weight(1f)) {
                Text(it.name)
                Hint(it.projectDir.toString())
            }
        }
    }
}

@Composable
fun ProjectSelectorHeader(filter: String, onFilterChanged: (String) -> Unit, onProjectSelectorOpened: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        TextField(
            value = filter,
            onValueChange = onFilterChanged,
            modifier = Modifier.weight(1f),
            undecorated = true,
            placeholder = {
                BasicText("Search projects", style = GhidraliteTypography.hint())
            },
            leadingIcon = {
                GhidraliteIcons.General.Search(Modifier.size(20.dp).padding(end = 2.dp))
            }
        )

        OutlinedButton(onClick = onProjectSelectorOpened) {
            Text("Open")
        }
    }
}