package io.github.garyttierney.ghidralite.standalone.ui.windows.workspace

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.window.ApplicationScope
import ghidra.framework.model.Project
import io.github.garyttierney.ghidralite.standalone.ui.viewModel
import io.github.garyttierney.ghidralite.standalone.ui.windows.workspace.titleBar.WorkspaceTitleBar
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.window.DecoratedWindow
import org.koin.compose.scope.KoinScope
import org.koin.core.annotation.KoinExperimentalAPI
import org.koin.mp.KoinPlatformTools

@OptIn(KoinExperimentalAPI::class)
@Composable
fun ApplicationScope.WorkspaceWindow(project: Project) {
    KoinScope(scopeDefinition = { createScope<Project>(KoinPlatformTools.generateId(), project) }) {
        val workspaceViewModel = viewModel<WorkspaceViewModel>()

        DecoratedWindow(onCloseRequest = {
            project.close()
            exitApplication()
        }) {
            WorkspaceTitleBar(viewModel = workspaceViewModel)

            Box(modifier = Modifier.fillMaxSize().background(JewelTheme.globalColors.paneBackground)) {

            }
        }
    }
}