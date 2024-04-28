package io.github.garyttierney.ghidralite.standalone.ui.components.surface

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import org.jetbrains.jewel.foundation.theme.JewelTheme

@Composable
fun Panel(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize()
            .background(JewelTheme.globalColors.paneBackground)
            .then(modifier)
    ) {
        content()
    }
}