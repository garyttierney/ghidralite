package io.github.garyttierney.ghidralite.ui.components.icons

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.intl.Locale
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.toUpperCase
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.foundation.theme.LocalContentColor
import kotlin.math.abs

data class ThemeColor(val light: Long, val dark: Long)

interface ColorPalette {
    companion object {
        fun <T> select(storage: Array<T>, seed: String? = null): T {
            val keyCode = seed?.let { abs(it.hashCode()) % storage.size } ?: 0

            return storage[keyCode]
        }
    }

    val gradients: Array<Pair<ThemeColor, ThemeColor>>

    fun gradient(seed: String? = null): Pair<ThemeColor, ThemeColor> = select(gradients, seed)
}


object RecentProjectsPalette : ColorPalette {
    override val gradients: Array<Pair<ThemeColor, ThemeColor>>
        get() {
            return arrayOf(
                ThemeColor(0xFFDB3D3C, 0xFFCE443C) to ThemeColor(0xFFFF8E42, 0xFFE77E41),
                ThemeColor(0xFFF57236, 0xFFE27237) to ThemeColor(0xFFFCBA3F, 0xFFE8A83E),
                ThemeColor(0xFF2BC8BB, 0xFF2DBCAD) to ThemeColor(0xFF36EBAE, 0xFF35D6A4),
                ThemeColor(0xFF359AF2, 0xFF3895E1) to ThemeColor(0xFF57DBFF, 0xFF51C5EA),
                ThemeColor(0xFF8379FB, 0xFF7B75E8) to ThemeColor(0xFF85A8FF, 0xFF7D99EB),
                ThemeColor(0xFF7E54B5, 0xFF7854AD) to ThemeColor(0xFF9486FF, 0xFF897AE6),
                ThemeColor(0xFFD63CC8, 0xFF8F4593) to ThemeColor(0xFFF582B9, 0xFFB572E3),
                ThemeColor(0xFF954294, 0xFFC840B9) to ThemeColor(0xFFC87DFF, 0xFFE074AE),
                ThemeColor(0xFFE75371, 0xFFD75370) to ThemeColor(0xFFFF78B5, 0xFFE96FA3)
            )
        }
}

@Composable
fun PlaceholderIcon(text: String) {
    val textMeasurer = rememberTextMeasurer()

    Box(modifier = Modifier.size(32.dp), contentAlignment = Alignment.Center) {
        val color = LocalContentColor.current
        val gradient = RecentProjectsPalette.gradient(text)
        val isDark = JewelTheme.isDark

        val colors = listOf(
            Color(if (isDark) gradient.first.dark else gradient.first.light),
            Color(if (isDark) gradient.second.dark else gradient.second.light),
        )

        val style = JewelTheme.defaultTextStyle.copy(color = color)

        Canvas(modifier = Modifier.size(32.dp)) {
            drawRoundRect(
                brush = Brush.horizontalGradient(colors = colors),
                cornerRadius = CornerRadius(x = 6f, y = 6f),
            )

            val layoutResult = textMeasurer.measure(
                text = text.substring(0, 2).toUpperCase(Locale.current),
                style = style
            )

            val offset = Alignment.Center.align(layoutResult.size, IntSize(32, 32), LayoutDirection.Ltr)

            drawText(
                textLayoutResult = layoutResult,
                topLeft = Offset(offset.x.toFloat(), offset.y.toFloat()),
                textDecoration = style.textDecoration,
                shadow = style.shadow,
            )
        }
    }
}