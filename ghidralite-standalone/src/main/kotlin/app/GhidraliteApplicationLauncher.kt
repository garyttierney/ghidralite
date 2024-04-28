package io.github.garyttierney.ghidralite.standalone.app

import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.configureSwingGlobalsForCompose
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.window.application
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
import ghidra.framework.Application
import ghidra.framework.ApplicationConfiguration
import ghidra.framework.ModuleInitializer
import ghidra.util.classfinder.ClassSearcher
import ghidra.util.task.TaskMonitor
import io.github.classgraph.ClassGraph
import io.github.garyttierney.ghidralite.standalone.app.data.UserDataStore
import io.github.garyttierney.ghidralite.standalone.app.modules.ProjectModule
import io.github.garyttierney.ghidralite.standalone.app.task.ApplicationTaskRunner
import io.github.garyttierney.ghidralite.standalone.app.task.LocalApplicationTaskRunner
import io.github.garyttierney.ghidralite.standalone.app.ui.GhidraliteApplicationRoot
import io.github.garyttierney.ghidralite.standalone.app.ui.GhidraliteApplicationViewModel
import io.github.garyttierney.ghidralite.standalone.app.ui.views.startup.StartupScreenModule
import io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.WorkspaceScreenModule
import io.github.garyttierney.ghidralite.standalone.ui.rememberComposeViewModelStoreOwner
import org.jetbrains.jewel.foundation.ExperimentalJewelApi
import org.jetbrains.jewel.foundation.enableNewSwingCompositing
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.intui.standalone.Inter
import org.jetbrains.jewel.intui.standalone.theme.IntUiTheme
import org.jetbrains.jewel.intui.standalone.theme.createDefaultTextStyle
import org.jetbrains.jewel.intui.standalone.theme.darkThemeDefinition
import org.jetbrains.jewel.intui.standalone.theme.default
import org.jetbrains.jewel.intui.window.decoratedWindow
import org.jetbrains.jewel.intui.window.styling.dark
import org.jetbrains.jewel.ui.ComponentStyling
import org.jetbrains.jewel.window.styling.TitleBarStyle
import org.koin.compose.KoinContext
import org.koin.core.context.startKoin
import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module
import utility.application.ApplicationLayout


class GhidraliteApplicationLauncher {
    @OptIn(ExperimentalComposeUiApi::class, ExperimentalJewelApi::class)
    fun launch(layout: ApplicationLayout, args: Array<out String>?) {
        Thread.currentThread().name = "Ghidralite"
        configureSwingGlobalsForCompose(
            overrideLookAndFeel = true, useScreenMenuBarOnMacOs = true, useAutoDpiOnLinux = true
        )
        enableNewSwingCompositing()

        val dataStore = UserDataStore()

        // Several plugins use Application instead of the respective APIs to get data,
        // this is an upstream issue.
        Application.initializeApplication(layout, ApplicationConfiguration())

        val instances = ClassGraph()
            .enableClassInfo()
            .enableExternalClasses()
            .scan().use { scanResult ->
                scanResult.getClassesImplementing(ModuleInitializer::class.java)
                    .loadClasses()
                    .mapNotNull { it.getConstructor().newInstance() as? ModuleInitializer }
            }

        val taskRunner = ApplicationTaskRunner()

        instances.forEach { instance -> instance.run() }
        ClassSearcher.search(TaskMonitor.DUMMY)

        val koinApp = startKoin {
            modules(module {
                single { dataStore }
                factoryOf(::GhidraliteApplicationViewModel)
                includes(ProjectModule, StartupScreenModule, WorkspaceScreenModule)
            })
        }

        application(exitProcessOnExit = false) {
            KoinContext(context = koinApp.koin) {
                val textStyle = JewelTheme.createDefaultTextStyle(fontFamily = FontFamily.Inter)
                val themeDefinition = JewelTheme.darkThemeDefinition(defaultTextStyle = textStyle)

                IntUiTheme(
                    theme = themeDefinition,
                    styling = ComponentStyling.default().decoratedWindow(
                        titleBarStyle = TitleBarStyle.dark()
                    ),
                    swingCompatMode = true,
                ) {
                    CompositionLocalProvider(
                        LocalApplicationTaskRunner provides taskRunner,
                        LocalViewModelStoreOwner provides rememberComposeViewModelStoreOwner(),
                    ) {
                        GhidraliteApplicationRoot()
                    }
                }
            }
        }

        dataStore.flush()
    }

}