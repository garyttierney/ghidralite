package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import ghidra.framework.model.DomainFile
import ghidra.program.database.ProgramDB
import ghidra.util.task.TaskMonitor
import org.koin.core.annotation.Scope
import org.koin.core.annotation.Scoped

@Scoped
@Scope(Workspace::class)
class WorkspaceViewModel(val project: Workspace) : ViewModel() {
    fun changeProgram(file: DomainFile) {
        activeProgram?.release(this)
        activeProgram = file.getDomainObject(this, false, false, TaskMonitor.DUMMY) as ProgramDB
    }

    var activeProgram by mutableStateOf<ProgramDB?>(null)
}