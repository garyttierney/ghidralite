package io.github.garyttierney.ghidralite.standalone.app.ui.views.startup.projectSelector

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import ghidra.framework.model.ProjectLocator
import ghidra.program.database.ProgramDB
import io.github.garyttierney.ghidralite.core.ProjectRepository
import io.github.garyttierney.ghidralite.core.project.walk
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.Workspace
import org.koin.core.annotation.Factory

@Factory
class ProjectSelectorViewModel(
    private val projects: ProjectRepository,
) : ViewModel() {
    // TODO: move this out of the view model
    suspend fun loadWorkspace(path: ProjectLocator): Workspace {
        val project = projects.load(path)
        val programFiles = project.projectData.rootFolder
            .walk()
            .filter { it.domainObjectClass == ProgramDB::class.java }

        return Workspace(project, programFiles.toList())
    }

    val recentProjects = projects.recentProjects()
    var projectFilter by mutableStateOf("")
    var openProjectFileSelector by mutableStateOf(false)
}