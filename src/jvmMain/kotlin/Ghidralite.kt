@file:OptIn(ExperimentalComposeUiApi::class)

import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.SwingPanel
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.res.ResourceLoader
import androidx.compose.ui.res.loadSvgPainter
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.Density
import androidx.compose.ui.window.application
import docking.Tool
import generic.theme.ApplicationThemeManager
import generic.theme.builtin.FlatDarkTheme
import ghidra.GhidraApplicationLayout
import ghidra.GhidraLaunchable
import ghidra.GhidraLauncher
import ghidra.app.util.viewer.format.FormatManager
import ghidra.app.util.viewer.listingpanel.ListingPanel
import ghidra.framework.Application
import ghidra.framework.GhidraApplicationConfiguration
import ghidra.framework.model.ProjectLocator
import ghidra.framework.options.ToolOptions
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidracore.GhidraliteProjectManager
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.intui.standalone.Inter
import org.jetbrains.jewel.intui.standalone.theme.IntUiTheme
import org.jetbrains.jewel.intui.standalone.theme.createDefaultTextStyle
import org.jetbrains.jewel.intui.standalone.theme.darkThemeDefinition
import org.jetbrains.jewel.intui.standalone.theme.default
import org.jetbrains.jewel.intui.window.decoratedWindow
import org.jetbrains.jewel.intui.window.styling.dark
import org.jetbrains.jewel.ui.ComponentStyling
import org.jetbrains.jewel.ui.component.Text
import org.jetbrains.jewel.window.DecoratedWindow
import org.jetbrains.jewel.window.TitleBar
import org.jetbrains.jewel.window.styling.TitleBarStyle
import java.io.InputStream
import javax.swing.SwingUtilities

class Ghidralite : GhidraLaunchable {
    override fun launch(layout: GhidraApplicationLayout, args: Array<out String>) {
        Application.initializeApplication(layout, GhidraApplicationConfiguration())
        SwingUtilities.invokeLater {
            ApplicationThemeManager.getInstance().setTheme(FlatDarkTheme())
        }

        val icon = svgResource("icons/jewel-logo.svg")
        val projectManager = GhidraliteProjectManager()
        val projectLocator = ProjectLocator("/home/gtierney", "android.gpr")
        val project = projectManager.openProject(projectLocator, false, false)
        val file = project.getProjectData(projectLocator).getFile("/eldenring.exe")
        val program = file.getDomainObject(this, false, false, TaskMonitor.DUMMY) as Program

        val listing = ListingPanel(FormatManager(ToolOptions("_unused"), ToolOptions("Listing Fields")), program)
        application {
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
                    icon = icon,
                ) {
                    TitleBar { Text("Ghidralite") }
                    SwingPanel(
                        modifier = Modifier.fillMaxWidth().fillMaxHeight(),
                        factory = {
                            listing
                        },
                    )
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