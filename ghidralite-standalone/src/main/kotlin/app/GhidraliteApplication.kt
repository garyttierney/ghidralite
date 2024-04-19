package io.github.garyttierney.ghidralite.standalone.app

import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.configureSwingGlobalsForCompose
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.window.application
import ghidra.framework.Application
import ghidra.framework.ApplicationConfiguration
import io.github.garyttierney.ghidralite.standalone.app.data.UserDataStore
import io.github.garyttierney.ghidralite.standalone.app.modules.projectModule
import io.github.garyttierney.ghidralite.standalone.ui.startup.StartupScreen
import io.github.garyttierney.ghidralite.standalone.ui.startup.StartupViewModel
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
import org.koin.core.module.dsl.factoryOf
import org.koin.dsl.module
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

        val appModule = module {
            single { dataStore }
            factoryOf(::StartupViewModel)
        }

        val koinApp = startKoin {
            modules(appModule, projectModule)
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
                    withViewModelStoreOwner {
                        StartupScreen()
                    }
                }
            }
        }

        dataStore.flush()
    }

}