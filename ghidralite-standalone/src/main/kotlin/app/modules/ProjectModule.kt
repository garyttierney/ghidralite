package io.github.garyttierney.ghidralite.standalone.app.modules

import io.github.garyttierney.ghidralite.core.ProjectRepository
import io.github.garyttierney.ghidralite.core.project.GhidraliteProjectManager
import io.github.garyttierney.ghidralite.standalone.app.ui.views.startup.projectSelector.ProjectSelectorViewModel
import org.koin.core.module.dsl.factoryOf
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module

val ProjectModule = module {
    singleOf(::GhidraliteProjectManager)
    singleOf(::ProjectRepository)

    factoryOf(::ProjectSelectorViewModel)
}