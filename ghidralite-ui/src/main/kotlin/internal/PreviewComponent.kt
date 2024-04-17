package internal

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.*
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

@Composable
internal fun PreviewComponent(content: @Composable() () -> Unit) {
    val textStyle = JewelTheme.createDefaultTextStyle(fontFamily = FontFamily.Inter)
    val themeDefinition = JewelTheme.darkThemeDefinition(defaultTextStyle = textStyle)

    IntUiTheme(
        theme = themeDefinition,
        styling = ComponentStyling.default().decoratedWindow(
            titleBarStyle = TitleBarStyle.dark(),
        ),
        swingCompatMode = true,
    ) {
        Box(modifier = Modifier.background(themeDefinition.globalColors.paneBackground).fillMaxSize()) {
            content()
        }
    }
}