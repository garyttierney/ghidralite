package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace

import androidx.compose.runtime.*
import ghidra.framework.model.DomainFile
import ghidra.framework.model.Project

val LocalWorkspace: ProvidableCompositionLocal<Workspace> =
    staticCompositionLocalOf {
        error("No ContentColor provided. Have you forgotten the theme?")
    }

class Workspace(val project: Project, val programFiles: List<DomainFile>) {
    fun close() {
        project.close()
    }
}