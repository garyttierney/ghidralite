package io.github.garyttierney.ghidralite.standalone.app.modules

import io.github.garyttierney.ghidralite.standalone.ui.windows.startup.StartupScreenModule
import io.github.garyttierney.ghidralite.standalone.ui.windows.workspace.WorkspaceModule
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Module

@Module(
    includes = [
        StartupScreenModule::class,
        WorkspaceModule::class
    ]
)
@ComponentScan
class UiModule