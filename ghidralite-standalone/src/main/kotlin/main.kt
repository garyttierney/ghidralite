package io.github.garyttierney.ghidralite.standalone

import io.github.garyttierney.ghidralite.standalone.app.GhidraliteApplicationLauncher
import io.github.garyttierney.ghidralite.standalone.app.GhidraliteApplicationLayout

fun main(args: Array<String>) {
    val layout = GhidraliteApplicationLayout()
    GhidraliteApplicationLauncher().launch(layout, args)
}