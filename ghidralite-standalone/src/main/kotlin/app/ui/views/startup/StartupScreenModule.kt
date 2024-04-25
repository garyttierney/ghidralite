package io.github.garyttierney.ghidralite.standalone.app.ui.views.startup

import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module

val StartupScreenModule = module {
    factoryOf(::StartupViewModel)
}