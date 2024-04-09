@file:OptIn(ExperimentalComposeUiApi::class)

package io.github.garyttierney.ghidralite

import androidx.compose.ui.*
import androidx.compose.ui.graphics.painter.*
import androidx.compose.ui.res.*
import androidx.compose.ui.text.font.*
import androidx.compose.ui.unit.*
import androidx.compose.ui.window.*
import generic.theme.ApplicationThemeManager
import generic.theme.builtin.FlatDarkTheme
import ghidra.GhidraApplicationLayout
import ghidra.GhidraLaunchable
import ghidra.GhidraLauncher
import ghidra.framework.Application
import ghidra.framework.GhidraApplicationConfiguration
import io.github.garyttierney.ghidralite.ui.root.GhidraliteRoot
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
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
import java.io.InputStream
import java.util.concurrent.Executors
import javax.swing.SwingUtilities

val GhidraWorkerScope = CoroutineScope(SupervisorJob() + Executors.newWorkStealingPool().asCoroutineDispatcher())
val GhidraWorkerContext = GhidraWorkerScope.coroutineContext

class Ghidralite : GhidraLaunchable {
    override fun launch(layout: GhidraApplicationLayout, args: Array<out String>) {

        Application.initializeApplication(layout, GhidraApplicationConfiguration())

        SwingUtilities.invokeLater {
            ApplicationThemeManager.getInstance().setTheme(FlatDarkTheme())
        }

        val icon = svgResource("icons/jewel-logo.svg")

        application {
            val windowState = rememberWindowState()

            val textStyle = JewelTheme.createDefaultTextStyle(fontFamily = FontFamily.Inter)
            val themeDefinition = JewelTheme.darkThemeDefinition(defaultTextStyle = textStyle)

            IntUiTheme(
                theme = themeDefinition,
                styling = ComponentStyling.default().decoratedWindow(
                    titleBarStyle = TitleBarStyle.dark(),
                ),
                swingCompatMode = true,
            ) {
                DecoratedWindow(
                    onCloseRequest = { exitApplication() },
                    state = windowState,
                    icon = icon
                ) {
                    GhidraliteRoot()
                }
            }
        }
    }
}


fun main(args: Array<out String>) {
    val ghidraArgs = arrayOf(Ghidralite::class.qualifiedName)
    args.copyInto(ghidraArgs, destinationOffset = 1)

    GhidraLauncher.launch(ghidraArgs)
}

private fun svgResource(
    resourcePath: String,
    loader: ResourceLoader = ResourceLoader.Default,
): Painter =
    loader.load(resourcePath)
        .use { stream: InputStream ->
            loadSvgPainter(stream, Density(1f))
        }