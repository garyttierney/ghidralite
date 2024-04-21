package io.github.garyttierney.ghidralite.standalone.ui.windows.workspace

import androidx.compose.runtime.mutableStateListOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ghidra.framework.model.Project
import ghidra.program.database.ProgramDB
import io.github.garyttierney.ghidralite.core.project.walk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.koin.core.annotation.Scope
import org.koin.core.annotation.Scoped

@Scope(Project::class)
@Scoped
class WorkspaceViewModel(val project: Project) : ViewModel() {
    val programs = mutableStateListOf<String>()


    init {
        viewModelScope.launch(Dispatchers.IO) {
            project.projectData.rootFolder.walk()
                .filter { it.domainObjectClass == ProgramDB::class.java }
                .map { it.pathname }
                .toCollection(programs)
        }
    }
}