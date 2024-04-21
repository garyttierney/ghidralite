package io.github.garyttierney.ghidralite.standalone.ui.components.list

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsHoveredAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.PointerIcon
import androidx.compose.ui.input.pointer.pointerHoverIcon
import androidx.compose.ui.unit.dp
import org.jetbrains.jewel.foundation.lazy.SelectableLazyColumn
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.theme.menuStyle
import java.awt.Cursor


@Composable
fun <T : Any> SelectableList(
    selectableListModel: SelectableListModel<T>,
    modifier: Modifier = Modifier,
    onItemSelected: (T) -> Unit,
    itemContent: @Composable (T) -> Unit,
) {
    SelectableLazyColumn(modifier = modifier) {
        items(
            count = selectableListModel.count(),
            key = { it },
            contentType = { "same" }
        ) {
            val interactionSource = remember { MutableInteractionSource() }
            val isHovered by interactionSource.collectIsHoveredAsState()
            val item = selectableListModel.item(it)

            val bg = when {
                isSelected || isActive || isHovered -> Modifier.background(
                    color = JewelTheme.menuStyle.colors.itemColors.backgroundFocused,
                    shape = RoundedCornerShape(4.dp)
                )

                else -> Modifier
            }

            val interaction = Modifier.clickable { onItemSelected(item) }.hoverable(interactionSource).pointerHoverIcon(
                PointerIcon(
                    Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                )
            )

            Box(modifier = Modifier.fillMaxWidth().then(bg).then(interaction).padding(8.dp)) {
                itemContent(item)
            }
        }
    }
}