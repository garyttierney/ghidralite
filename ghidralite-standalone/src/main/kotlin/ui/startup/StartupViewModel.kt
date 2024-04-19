package io.github.garyttierney.ghidralite.standalone.ui.startup

import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.referentialEqualityPolicy
import androidx.compose.runtime.toMutableStateList
import androidx.lifecycle.ViewModel
import ghidra.framework.model.Project
import io.github.garyttierney.ghidralite.standalone.app.data.UserData
import io.github.garyttierney.ghidralite.standalone.project.ProjectLoader
import io.github.garyttierney.ghidralite.standalone.project.recent.RecentProjectsData

class StartupViewModel(
    val projectLoader: ProjectLoader,
    recentProjectsData: UserData<RecentProjectsData>
) : ViewModel() {

    val openedProject = mutableStateOf<Project?>(null, referentialEqualityPolicy())
    val recentProjects = recentProjectsData.value.projects.toMutableStateList()
}