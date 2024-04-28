package io.github.garyttierney.ghidralite.standalone.app.ui.views.startup

sealed interface StartupScreenOption {
    data object ProjectSelector : StartupScreenOption
}
