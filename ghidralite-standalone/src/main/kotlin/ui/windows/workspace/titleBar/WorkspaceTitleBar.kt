package io.github.garyttierney.ghidralite.standalone.ui.windows.workspace.titleBar

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.loadSvgPainter
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteIcons
import io.github.garyttierney.ghidralite.standalone.ui.windows.workspace.WorkspaceViewModel
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette
import org.jetbrains.jewel.window.DecoratedWindowScope
import org.jetbrains.jewel.window.TitleBar
import org.jetbrains.jewel.window.newFullscreenControls
import java.awt.Desktop
import java.net.URI


@OptIn(ExperimentalFoundationApi::class)
@Composable
fun DecoratedWindowScope.WorkspaceTitleBar(viewModel: WorkspaceViewModel) {
    TitleBar(Modifier.newFullscreenControls(), gradientStartColor = JewelTheme.colorPalette.red(3)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(horizontal = 8.dp).align(Alignment.Start)
        ) {
            IconButton(onClick = {}) {
                GhidraliteIcons.General.WindowMenu(Modifier.size(20.dp))
            }

            Dropdown(Modifier.height(30.dp), menuContent = {
                viewModel.programs.forEach {
                    selectableItem(
                        selected = false,
                        onClick = {
                        },
                    ) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(it)
                        }
                    }
                }
            }) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(3.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("No active program")
                    }
                }
            }
        }

        Text(title)

        Row(Modifier.align(Alignment.End)) {
            Tooltip({
                Text("Ghidralite GitHub")
            }) {
                IconButton({
                    Desktop.getDesktop().browse(URI.create("https://github.com/garyttierney/ghidralite"))
                }, Modifier.size(40.dp).padding(5.dp)) {
                    Icon("/vcs/vendors/github_dark.svg", "Github", GhidraliteIcons::class.java)
                }
            }
        }
    }
}