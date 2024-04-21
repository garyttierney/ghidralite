package io.github.garyttierney.ghidralite.standalone.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.configureSwingGlobalsForCompose
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.window.application
import ghidra.framework.Application
import ghidra.framework.ApplicationConfiguration
import ghidra.framework.ModuleInitializer
import ghidra.framework.model.Project
import ghidra.util.classfinder.ClassSearcher
import ghidra.util.task.TaskMonitor
import io.github.classgraph.ClassGraph
import io.github.garyttierney.ghidralite.standalone.app.data.UserDataStore
import io.github.garyttierney.ghidralite.standalone.app.modules.ProjectModule
import io.github.garyttierney.ghidralite.standalone.app.modules.UiModule
import io.github.garyttierney.ghidralite.standalone.ui.windows.startup.StartupWindow
import io.github.garyttierney.ghidralite.standalone.ui.windows.workspace.WorkspaceWindow
import io.github.garyttierney.ghidralite.standalone.ui.withViewModelStoreOwner
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
import org.koin.dsl.module
import org.koin.ksp.generated.module
import utility.application.ApplicationLayout


class GhidraliteApplication {
    @OptIn(ExperimentalComposeUiApi::class)
    fun launch(layout: ApplicationLayout, args: Array<out String>?) {
        configureSwingGlobalsForCompose(
            overrideLookAndFeel = true, useScreenMenuBarOnMacOs = true, useAutoDpiOnLinux = true
        )

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


        instances.forEach { instance -> instance.run() }
        ClassSearcher.search(TaskMonitor.DUMMY)

        val koinApp = startKoin {
            modules(module {
                single { dataStore }
                includes(ProjectModule().module, UiModule().module)
            })
        }

        application(exitProcessOnExit = false) {
            KoinContext(context = koinApp.koin) {
                val textStyle = JewelTheme.createDefaultTextStyle(fontFamily = FontFamily.Inter)
                val themeDefinition = JewelTheme.darkThemeDefinition(defaultTextStyle = textStyle)
                var openedProject by remember { mutableStateOf<Project?>(null) }

                IntUiTheme(
                    theme = themeDefinition,
                    styling = ComponentStyling.default().decoratedWindow(
                        titleBarStyle = TitleBarStyle.dark()
                    ),
                    swingCompatMode = true,
                ) {
                    withViewModelStoreOwner {
                        val project = openedProject
                        if (project != null) {
                            WorkspaceWindow(project = project)
                        } else {
                            StartupWindow(onProjectOpened = { openedProject = it })
                        }
                    }
                }
            }
        }

        dataStore.flush()
    }

}