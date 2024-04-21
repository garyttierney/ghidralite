package io.github.garyttierney.ghidralite.standalone.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.sp
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.colorPalette

object GhidraliteTypography {
    @Composable
    fun hint() = with(JewelTheme) {
        defaultTextStyle.merge(
            fontSize = Typography.labelTextSize() - 1.sp,
            color = colorPalette.grey(7)
        )
    }
}