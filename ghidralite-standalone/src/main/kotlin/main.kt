package io.github.garyttierney.ghidralite.standalone

import io.github.garyttierney.ghidralite.standalone.app.GhidraliteApplication
import io.github.garyttierney.ghidralite.standalone.app.GhidraliteApplicationLayout

fun main(args: Array<String>) {
    val layout = GhidraliteApplicationLayout()
    GhidraliteApplication().launch(layout, args)
}