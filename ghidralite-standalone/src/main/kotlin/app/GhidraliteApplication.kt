package io.github.garyttierney.ghidralite.standalone.app

import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.configureSwingGlobalsForCompose
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.window.application
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.intui.standalone.Inter
import org.jetbrains.jewel.intui.standalone.theme.IntUiTheme
import org.jetbrains.jewel.intui.standalone.theme.createDefaultTextStyle
import org.jetbrains.jewel.intui.standalone.theme.darkThemeDefinition
import org.jetbrains.jewel.intui.standalone.theme.default
import org.jetbrains.jewel.intui.window.decoratedWindow
import org.jetbrains.jewel.intui.window.styling.dark
import org.jetbrains.jewel.ui.ComponentStyling
import org.jetbrains.jewel.window.DecoratedWindow
import org.jetbrains.jewel.window.styling.TitleBarStyle
import utility.application.ApplicationLayout

class GhidraliteApplication() {
    @OptIn(ExperimentalComposeUiApi::class)
    fun launch(layout: ApplicationLayout, args: Array<out String>?) {
        configureSwingGlobalsForCompose(
            overrideLookAndFeel = true,
            useScreenMenuBarOnMacOs = true,
            useAutoDpiOnLinux = true
        )

        application {
            val textStyle = JewelTheme.createDefaultTextStyle(fontFamily = FontFamily.Inter)

            val themeDefinition =
                JewelTheme.darkThemeDefinition(defaultTextStyle = textStyle)

            IntUiTheme(
                theme = themeDefinition,
                styling = ComponentStyling.default().decoratedWindow(
                    titleBarStyle = TitleBarStyle.dark()
                ),
                swingCompatMode = true,
            ) {
                DecoratedWindow(
                    onCloseRequest = { exitApplication() },
                    title = "Jewel standalone sample",
                ) {
                }
            }
        }
    }
}