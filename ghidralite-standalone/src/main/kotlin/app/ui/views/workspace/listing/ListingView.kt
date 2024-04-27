package io.github.garyttierney.ghidralite.standalone.app.ui.views.workspace.listing

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.selection.DisableSelection
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.layout
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.platform.Font
import androidx.compose.ui.unit.dp
import ghidra.app.util.viewer.util.AddressIndexMap
import ghidra.program.database.ProgramDB
import ghidra.program.model.listing.CodeUnit
import io.github.garyttierney.ghidralite.standalone.ui.theme.GhidraliteTypography
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*
import java.math.BigInteger

fun Modifier.withoutWidthConstraints() = layout { measurable, constraints ->
    val placeable = measurable.measure(constraints.copy(maxWidth = Int.MAX_VALUE))
    layout(constraints.maxWidth, placeable.height) {
        placeable.place(0, 0)
    }
}

@Composable
fun ListingView(modifier: Modifier, program: ProgramDB) {
    val addressMap = remember { AddressIndexMap(program.memory.initializedAddressSet) }
    val addressIndices by derivedStateOf { addressMap.indexCount.toInt() }
    val textStyle = JewelTheme.defaultTextStyle.copy(fontFamily = FontFamily(Font("/fonts/JetBrainsMono[wght].ttf")))

    LazyColumn {

        items(addressIndices) {
            val address = addressMap.getAddress(BigInteger.valueOf(it.toLong()))
            val codeUnit = program.codeManager.getCodeUnitAt(address)

            if (codeUnit == null) {
                Box() {}
            } else {
                Box {
                    Line(codeUnit, textStyle)
                }
            }
        }
    }

}

@Composable
private fun BoxScope.Line(
    codeUnit: CodeUnit, textStyle: TextStyle
) {
    Row(Modifier.align(Alignment.CenterStart)) {
        DisableSelection {
            BasicText(
                codeUnit.address.toString(),
                style = GhidraliteTypography.hint().merge(textStyle),
                modifier = Modifier.width(128.dp),
            )
        }

        Text(
            text = codeUnit.mnemonicString,
            style = textStyle,
            modifier = Modifier.weight(1f).withoutWidthConstraints().padding(start = 28.dp, end = 12.dp)
        )
    }
}
