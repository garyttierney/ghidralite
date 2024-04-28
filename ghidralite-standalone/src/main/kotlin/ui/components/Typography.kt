package io.github.garyttierney.ghidralite.standalone.ui.components

import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteTypography

@Composable
fun Hint(text: String) {
    BasicText(text, style = GhidraliteTypography.hint())
}