package io.github.garyttierney.ghidralite.standalone.ui.windows.startup.projectSelector

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ghidra.framework.model.Project
import io.github.garyttierney.ghidralite.core.ProjectRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.koin.core.annotation.Factory
import java.nio.file.Path

@Factory
class ProjectSelectorViewModel(
    private val projects: ProjectRepository,
) : ViewModel() {
    fun openProject(path: Path, onProjectOpened: (Project) -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            val project = projects.load(path)
            val files = project.projectData.rootFolder

            onProjectOpened(project)
        }
    }

    val recentProjects = projects.recentProjects()
    var projectFilter by mutableStateOf("")
    var openProjectFileSelector by mutableStateOf(false)
}