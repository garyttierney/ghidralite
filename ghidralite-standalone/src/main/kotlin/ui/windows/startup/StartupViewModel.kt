package io.github.garyttierney.ghidralite.standalone.ui.windows.startup

import androidx.compose.runtime.*
import androidx.lifecycle.ViewModel
import ghidra.framework.model.Project
import io.github.garyttierney.ghidralite.core.ProjectRepository
import io.github.garyttierney.ghidralite.standalone.app.data.UserData
import io.github.garyttierney.ghidralite.standalone.project.recent.RecentProjectsData
import org.koin.core.annotation.Factory

@Factory
class StartupViewModel(
    private val projectLoader: ProjectRepository,
) : ViewModel() {
    var selectedOption by mutableStateOf(StartupScreenOption.ProjectSelector)
}