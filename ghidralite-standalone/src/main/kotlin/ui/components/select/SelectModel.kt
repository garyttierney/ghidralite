package io.github.garyttierney.ghidralite.standalone.ui.components.select

import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.remember


@Stable
interface SelectionModel<ItemT> {
    fun count(): Int
    fun item(key: Int): ItemT
}

@Composable
fun <T> rememberSelectionModel(
    items: List<T>,
): SelectionModel<T> {
    return remember {
        val listModel = object : SelectionModel<T> {
            override fun count() = items.size
            override fun item(key: Int) = items[key]
        }

        listModel
    }
}
