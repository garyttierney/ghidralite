package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.titleBar

import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.lifecycle.ViewModel
import ghidra.framework.model.Project
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.Workspace
import org.koin.core.annotation.Scope
import org.koin.core.annotation.Scoped

@Scoped
@Scope(Workspace::class)
class WorkspaceTitleBarViewModel(val project: Project) : ViewModel() {
    val programs by derivedStateOf {
        project.projectData.rootFolder.files.mapNotNull {
            it.getDomainObject(
                this,
                false,
                false,
                TaskMonitor.DUMMY
            ) as? Program
        }
    }
}