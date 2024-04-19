package io.github.garyttierney.ghidralite.standalone.project.recent

import io.github.garyttierney.ghidralite.standalone.app.data.UserData
import kotlinx.serialization.Serializable
import java.nio.file.Path

@Serializable
data class RecentProject(val name: String, val path: Path)

@Serializable
data class RecentProjectsData(val projects: List<RecentProject> = mutableListOf())