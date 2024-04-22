package io.github.garyttierney.ghidralite.core.index.change

sealed interface IndexChange<T> {
    val value: T

    data class Added<T>(override val value: T) : IndexChange<T>
    data class Replaced<T>(override val value: T) : IndexChange<T>
    data class Removed<T>(override val value: T) : IndexChange<T>
}