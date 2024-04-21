package io.github.garyttierney.ghidralite.standalone.ui.windows.workspace

import ghidra.framework.model.Project
import org.koin.core.annotation.ComponentScan
import org.koin.core.annotation.Module
import org.koin.core.annotation.Scope
import org.koin.core.annotation.Scoped

@Module
@ComponentScan
@Scope(value = Project::class)
class WorkspaceModule {

}