package io.github.garyttierney.ghidralite.standalone.ui.components.list

import androidx.compose.runtime.Composable
import androidx.compose.runtime.Stable
import androidx.compose.runtime.remember


@Stable
interface SelectableListModel<ItemT> {
    fun count(): Int
    fun item(key: Int): ItemT
    fun key(item: ItemT): Any
    fun labelSelector(item: ItemT): String
}

@Composable
fun <T> rememberListModel(
    items: List<T>,
    labelSelector: (T) -> String
): SelectableListModel<T> {

    return remember {
        val listModel = object : SelectableListModel<T> {
            override fun count() = items.size
            override fun item(key: Int) = items[key]
            override fun key(item: T) = items.indexOf(item)
            override fun labelSelector(item: T): String = labelSelector(item)
        }

        listModel
    }
}
