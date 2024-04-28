package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace

import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewModelScope
import io.github.garyttierney.ghidralite.standalone.app.task.rememberTaskRunner
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.listing.ListingView
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.statusBar.WorkspaceStatusBar
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.titleBar.WorkspaceTitleBar
import io.github.garyttierney.ghidralite.standalone.ui.components.surface.Panel
import io.github.garyttierney.ghidralite.standalone.ui.viewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.jetbrains.jewel.window.DecoratedWindowScope

@Composable
fun DecoratedWindowScope.WorkspaceView() {
    val workspaceViewModel = viewModel<WorkspaceViewModel>()
    val workspaceTaskRunner = rememberTaskRunner(workspaceViewModel.viewModelScope)

    WorkspaceTitleBar(
        programs = workspaceViewModel.project.programFiles,
        selectedProgram = workspaceViewModel.activeProgram?.domainFile,
        onProgramSelected = {
            workspaceTaskRunner.run("Loading program", modal = true) {
                withContext(Dispatchers.IO) {
                    workspaceViewModel.changeProgram(it)
                }
            }
        }
    )



    Panel {
        Column {
            workspaceViewModel.activeProgram?.let { program ->
                ListingView(modifier = Modifier.weight(1f), program = program)
            }
            WorkspaceStatusBar()
        }
    }
}

