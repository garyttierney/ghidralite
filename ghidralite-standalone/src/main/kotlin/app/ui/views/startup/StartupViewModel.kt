package io.github.garyttierney.ghidralite.standalone.app.ui.views.startup

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel


class StartupViewModel() : ViewModel() {
    var selectedOption by mutableStateOf<StartupScreenOption>(StartupScreenOption.ProjectSelector)
}