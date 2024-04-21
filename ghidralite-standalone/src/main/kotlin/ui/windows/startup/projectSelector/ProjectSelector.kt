package io.github.garyttierney.ghidralite.standalone.ui.windows.startup.projectSelector

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.darkrockstudios.libraries.mpfilepicker.FilePicker
import ghidra.framework.model.Project
import ghidra.framework.model.ProjectLocator
import io.github.garyttierney.ghidralite.standalone.ui.components.list.SelectableList
import io.github.garyttierney.ghidralite.standalone.ui.components.list.rememberListModel
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteIcons
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteTypography
import io.github.garyttierney.ghidralite.standalone.ui.viewModel
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.Orientation
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette
import java.io.File

@Composable
fun ProjectSelector(viewModel: ProjectSelectorViewModel = viewModel(), onProjectSelected: (Project) -> Unit) {
    ProjectSelectorHeader(viewModel)

    FilePicker(show = viewModel.openProjectFileSelector, fileExtensions = listOf("gpr")) {
        viewModel.openProjectFileSelector = false

        it?.let { path ->
            val file = path.platformFile as File
            val locator = ProjectLocator(file.parent, file.name)

            viewModel.openProject(locator) { project ->
                onProjectSelected(project)
            }
        }
    }

    Divider(
        orientation = Orientation.Horizontal,
        color = JewelTheme.colorPalette.grey(4),
        thickness = 1.dp,
        modifier = Modifier.padding(vertical = 8.dp)
    )

    val projectListModel = rememberListModel(viewModel.recentProjects) { it.name }
    fun onProjectLocatorSelected(locator: ProjectLocator) = viewModel.openProject(locator, onProjectSelected)

    SelectableList(
        selectableListModel = projectListModel,
        modifier = Modifier.fillMaxSize(),
        onItemSelected = ::onProjectLocatorSelected
    ) {
        Column {
            Text(it.name)
            BasicText(text = it.projectDir.toString(), style = GhidraliteTypography.hint())
        }
    }
}

@Composable
fun ProjectSelectorHeader(viewModel: ProjectSelectorViewModel) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        TextField(
            value = viewModel.projectFilter,
            onValueChange = { viewModel.projectFilter = it },
            modifier = Modifier.weight(1f),
            undecorated = true,
            placeholder = {
                BasicText("Search projects", style = GhidraliteTypography.hint())
            },
            leadingIcon = {
                GhidraliteIcons.General.Search(Modifier.size(20.dp).padding(end = 2.dp))
            }
        )

        OutlinedButton(onClick = { viewModel.openProjectFileSelector = true }) {
            Text("Open")
        }
    }
}