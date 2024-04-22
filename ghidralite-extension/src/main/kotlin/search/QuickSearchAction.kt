package io.github.garyttierney.ghidralite.extension.search

import androidx.compose.foundation.background
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.ComposePanel
import androidx.compose.ui.awt.ComposeWindow
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.onFocusEvent
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import docking.action.KeyBindingData
import ghidra.app.context.ProgramActionContext
import ghidra.app.context.ProgramContextAction
import ghidra.app.services.GoToService
import ghidra.app.util.viewer.listingpanel.ListingPanel
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SymbolType
import io.github.garyttierney.ghidralite.core.search.SearchResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.intui.standalone.Inter
import org.jetbrains.jewel.intui.standalone.theme.IntUiTheme
import org.jetbrains.jewel.intui.standalone.theme.createDefaultTextStyle
import org.jetbrains.jewel.intui.standalone.theme.darkThemeDefinition
import org.jetbrains.jewel.intui.standalone.theme.default
import org.jetbrains.jewel.ui.ComponentStyling
import search.QuickSearch
import java.awt.BorderLayout
import java.awt.DefaultKeyboardFocusManager
import java.awt.Dimension
import java.awt.KeyboardFocusManager
import java.awt.event.*
import java.awt.event.InputEvent.CTRL_DOWN_MASK
import java.awt.event.InputEvent.SHIFT_DOWN_MASK
import javax.swing.JFrame
import javax.swing.SwingUtilities
import javax.swing.WindowConstants
import kotlin.time.Duration.Companion.milliseconds
import androidx.compose.ui.input.key.KeyEvent as ComposeKeyEvent


class QuickSearchAction(
    private val quickSearchService: QuickSearchService,
    private val previewListing: ListingPanel,
    private val goToService: GoToService
) :
    ProgramContextAction("Open Quick Search", "ghidralite-search") {
    init {
        keyBindingData = KeyBindingData(KeyEvent.VK_N, CTRL_DOWN_MASK or SHIFT_DOWN_MASK)
    }

    override fun actionPerformed(ctx: ProgramActionContext) {

        val originalLocation = previewListing.cursorLocation

        val window = ComposeWindow()
        // creating ComposePanel
        window.defaultCloseOperation = WindowConstants.DISPOSE_ON_CLOSE
        window.isUndecorated = true
        window.size = Dimension(480, 360)

        val focusRequester = FocusRequester()
        val parentWindow = SwingUtilities.windowForComponent(ctx.sourceComponent)
        val popupOffset = Alignment.Center.align(
            IntSize(window.size.width, window.size.height),
            IntSize(parentWindow.width, parentWindow.height),
            LayoutDirection.Ltr
        )

        val kfm = DefaultKeyboardFocusManager()
        val oldKfm = KeyboardFocusManager.getCurrentKeyboardFocusManager()
        KeyboardFocusManager.setCurrentKeyboardFocusManager(kfm)

        window.setLocation(parentWindow.x + popupOffset.x, parentWindow.y + popupOffset.y)
        window.setContent {
            var wasFocused by remember { mutableStateOf(false) }
            var searchQuery by remember { mutableStateOf("") }
            var searchJob by remember { mutableStateOf<Job?>(null) }
            val searchResults = remember { mutableStateListOf<SearchResult>() }
            val scope = rememberCoroutineScope()

            fun closeWindow() {
                window.isVisible = false
                KeyboardFocusManager.setCurrentKeyboardFocusManager(oldKfm)
            }

            val textStyle = JewelTheme.createDefaultTextStyle(fontFamily = FontFamily.Inter)
            val themeDefinition = JewelTheme.darkThemeDefinition(defaultTextStyle = textStyle)

            window.addWindowFocusListener(object : WindowFocusListener {
                override fun windowGainedFocus(e: WindowEvent) = Unit
                override fun windowLostFocus(e: WindowEvent) = closeWindow()
            })

            val keyHandler = { event: ComposeKeyEvent ->
                when (event.key) {
                    Key.Enter -> {
                        closeWindow()

                        true
                    }

                    Key.Escape -> {
                        previewListing.goTo(originalLocation)
                        closeWindow()

                        true
                    }

                    else -> false
                }
            }

            IntUiTheme(
                theme = themeDefinition,
                styling = ComponentStyling.default(),
                swingCompatMode = true,
            ) {
                QuickSearch(
                    items = searchResults,
                    query = searchQuery,
                    modifier = Modifier
                        .background(themeDefinition.globalColors.paneBackground)
                        .onPreviewKeyEvent(keyHandler)
                        .onFocusEvent {
                            if (!it.isFocused && wasFocused) {
                                closeWindow()
                            } else if (it.isFocused && !wasFocused) {
                                wasFocused = true
                            }
                        },
                    focusRequester = focusRequester,
                    itemPreview = { item ->
                        LaunchedEffect(item.element.key) {
                            val sym = ctx.program.symbolTable.getSymbol(item.element.key as Long)
                            val ty = sym.symbolType
                            if (ty == SymbolType.FUNCTION && sym.isExternal) {
                                val fn = sym.`object` as Function
                                goToService.goToExternalLocation(fn.externalLocation, true)
                            } else {
                                goToService.goTo(sym.address)
                            }
                        }
                    },
                    onQueryChanged = {
                        searchQuery = it
                        searchJob?.cancel()
                        searchJob = scope.launch(Dispatchers.IO) {
                            quickSearchService.search(it, onResultAvailable = { results ->
                                searchResults.clear()
                                searchResults.addAll(results)
                            })
                        }
                    },
                    onResultSelected = {}
                )

                LaunchedEffect(Unit) {
                    // FIXME
                    delay(100.milliseconds)
                    focusRequester.requestFocus()
                }
            }
        }

        window.isVisible = true
    }
}