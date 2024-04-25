package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace

import org.koin.core.module.dsl.scopedOf
import org.koin.dsl.module

val WorkspaceScreenModule = module {
    scope<Workspace> {
        scopedOf(::WorkspaceViewModel)
    }
}