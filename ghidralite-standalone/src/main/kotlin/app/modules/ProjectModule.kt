package io.github.garyttierney.ghidralite.standalone.app.modules

import io.github.garyttierney.ghidralite.core.ProjectRepository
import io.github.garyttierney.ghidralite.core.project.GhidraliteProjectManager
import io.github.garyttierney.ghidralite.standalone.app.data.UserData
import io.github.garyttierney.ghidralite.standalone.app.data.UserDataStore
import io.github.garyttierney.ghidralite.standalone.project.recent.RecentProjectsData
import org.koin.core.annotation.Module
import org.koin.core.annotation.Scoped
import org.koin.core.annotation.Single

@Module
class ProjectModule {
    @Single
    fun recentProjects(store: UserDataStore): UserData<RecentProjectsData> = store.resolve()

    @Single
    fun gpm() = GhidraliteProjectManager()

    @Single
    fun projectRepository(gpm: GhidraliteProjectManager) = ProjectRepository(gpm)
}