package io.github.garyttierney.ghidralite.standalone.app.modules

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.CreationExtras
import io.github.garyttierney.ghidralite.standalone.app.data.UserDataStore
import io.github.garyttierney.ghidralite.standalone.project.ProjectLoader
import io.github.garyttierney.ghidralite.standalone.project.recent.RecentProjects
import io.github.garyttierney.ghidralite.standalone.project.recent.RecentProjectsData
import org.koin.compose.getKoin
import org.koin.core.module.KoinDslMarker
import org.koin.core.module.Module
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import kotlin.reflect.KClass

@KoinDslMarker
inline fun <reified T : Any> Module.userDataOf() = single {
    val storage = get<UserDataStore>()
    val data = storage.resolve<T>()

    data
}


val projectModule = module {
    singleOf<ProjectLoader>(::ProjectLoader)
    singleOf<RecentProjects>(::RecentProjects)

    userDataOf<RecentProjectsData>()
}