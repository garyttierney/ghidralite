package io.github.garyttierney.ghidralite.standalone.ui.windows.startup

sealed interface StartupScreenOption {
    data object ProjectSelector : StartupScreenOption
}
