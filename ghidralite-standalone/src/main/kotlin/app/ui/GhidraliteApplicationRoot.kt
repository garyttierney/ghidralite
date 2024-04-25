package io.github.garyttierney.ghidralite.standalone.app.ui

import androidx.compose.runtime.*
import androidx.compose.ui.res.painterResource
import io.github.garyttierney.ghidralite.standalone.app.ui.views.startup.StartupView
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.Workspace
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.WorkspaceView
import io.github.garyttierney.ghidralite.standalone.ui.viewModel
import org.jetbrains.jewel.window.DecoratedWindow
import org.jetbrains.jewel.window.DecoratedWindowScope
import org.koin.compose.scope.KoinScope
import org.koin.core.annotation.KoinExperimentalAPI
import org.koin.mp.KoinPlatformTools


@Stable
interface GhidraliteApplicationScreen {

    @Composable
    fun DecoratedWindowScope.content()

    @Stable
    data object StartupScreen : GhidraliteApplicationScreen {
        @Composable
        override fun DecoratedWindowScope.content() {
            StartupView()
        }
    }

    @Stable
    data class WorkspaceScreen(val workspace: Workspace) : GhidraliteApplicationScreen {
        @Composable
        @OptIn(KoinExperimentalAPI::class)
        override fun DecoratedWindowScope.content() {
            KoinScope(scopeDefinition = { createScope<Workspace>(KoinPlatformTools.generateId(), workspace) }) {
                WorkspaceView()
            }
        }
    }
}

interface ApplicationScreenHolder {
    val current: GhidraliteApplicationScreen

    fun replaceWith(screen: GhidraliteApplicationScreen) {
        close()
        open(screen)
    }

    fun open(screen: GhidraliteApplicationScreen)
    fun close()
}

val LocalApplicationScreenHolder: ProvidableCompositionLocal<ApplicationScreenHolder> =
    staticCompositionLocalOf {
        error("No ContentColor provided. Have you forgotten the theme?")
    }


@Composable
fun GhidraliteApplicationRoot(viewModel: GhidraliteApplicationViewModel = viewModel()) {
    val icon = painterResource("/icons/ghidralite.svg")

    for (screen in viewModel.screens) {
        key(screen) {
            CompositionLocalProvider(LocalApplicationScreenHolder provides object : ApplicationScreenHolder {
                override val current: GhidraliteApplicationScreen
                    get() = screen

                override fun open(screen: GhidraliteApplicationScreen) {
                    viewModel.screens.add(screen)
                }

                override fun close() {
                    viewModel.screens.remove(current)
                }
            }) {
                DecoratedWindow(
                    title = "Ghidralite",
                    icon = icon,
                    onCloseRequest = { viewModel.screens.remove(screen) }
                ) {
                    with(screen) {
                        content()
                    }
                }
            }
        }
    }
}