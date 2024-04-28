package io.github.garyttierney.ghidralite.standalone.app.ui

import androidx.compose.runtime.mutableStateListOf
import androidx.lifecycle.ViewModel

class GhidraliteApplicationViewModel : ViewModel() {
    val screens = mutableStateListOf<GhidraliteApplicationScreen>(GhidraliteApplicationScreen.StartupScreen)
}