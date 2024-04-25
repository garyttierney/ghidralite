package io.github.garyttierney.ghidralite.standalone.ui.components.select

import androidx.compose.desktop.ui.tooling.preview.Preview
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.garyttierney.ghidralite.ui.internal.PreviewComponent
import org.jetbrains.jewel.ui.Outline
import org.jetbrains.jewel.ui.component.*


@Composable
fun <T> SelectDropdown(
    model: SelectionModel<T>,
    selectedItem: T? = null,
    onItemSelected: (item: T) -> Unit,
    placeholder: @Composable () -> Unit = { Text("No item selected") },
    itemContent: @Composable (item: T) -> Unit
) {
    val count = model.count()

    Dropdown(Modifier.height(30.dp), menuContent = {
        for (index in 0.until(count)) {
            val item = model.item(index)

            selectableItem(
                selected = item == selectedItem,
                onClick = {
                    onItemSelected(item)
                },
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    itemContent(item)
                }
            }
        }
    }) {
        Row(
            horizontalArrangement = Arrangement.spacedBy(3.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (selectedItem != null) {
                    itemContent(selectedItem)
                } else {
                    placeholder()
                }
            }
        }
    }
}
