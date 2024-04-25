package io.github.garyttierney.ghidralite.standalone.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*

object GhidraliteIcons {
    private fun iconProvider(
        name: String,
        hasDark: Boolean = true,
    ): @Composable (modifier: Modifier) -> Unit {
        return { modifier ->
            val icon = if (JewelTheme.isDark && hasDark) {
                "${name}_dark.svg"
            } else {
                "$name.svg"
            }

            Icon(
                resource = icon,
                contentDescription = name,
                iconClass = GhidraliteIcons::class.java,
                modifier = modifier,
            )
        }
    }

    val Ghidralite = iconProvider("/icons/ghidralite", hasDark = false)

    object General {
        val Search = iconProvider("/expui/general/search")
        val WindowMenu = iconProvider("/expui/general/windowsMenu@20x20")
        val Settings = iconProvider("/expui/general/settings")
    }
}