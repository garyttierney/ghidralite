package io.github.garyttierney.ghidralite.core

import ghidra.framework.model.Project
import ghidra.framework.model.ProjectLocator
import io.github.garyttierney.ghidralite.core.project.GhidraliteProjectManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.file.Path
import kotlin.io.path.name

class ProjectRepository(val gpm: GhidraliteProjectManager) {

    fun recentProjects(): List<ProjectLocator> = gpm.recentProjects.toList()

    suspend fun load(path: ProjectLocator): Project {
        val project = withContext(Dispatchers.IO) {
            gpm.openProject(path, false, false)
        }

        return project
    }
}