package tree


import androidx.compose.desktop.ui.tooling.preview.Preview
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import internal.PreviewComponent
import org.jetbrains.jewel.foundation.ExperimentalJewelApi
import org.jetbrains.jewel.foundation.lazy.tree.Tree
import org.jetbrains.jewel.foundation.lazy.tree.buildTree
import org.jetbrains.jewel.foundation.lazy.tree.rememberTreeState
import org.jetbrains.jewel.foundation.theme.JewelTheme
import org.jetbrains.jewel.ui.component.*
import org.jetbrains.jewel.ui.theme.treeStyle

@OptIn(ExperimentalJewelApi::class)
@Preview
@Composable
fun ProgramTree() = PreviewComponent {
    var tree by remember {
        mutableStateOf(
            buildTree {
                addNode("namespace 1", 1) {

                    addLeaf("class 1")
                    addLeaf("class 2")
                }
                addNode("namespace 2", 2) {
                    addLeaf("class 2.1")
                    addNode("class 2.2", 3) {
                        addLeaf("subclass 1") {

                        }
                        addLeaf("subclass 2")
                    }
                }
                addNode("namespace 3") {
                    addLeaf("class 3.1")
                    addLeaf("class 3.2")
                }
            },
        )
    }


    val treeState = rememberTreeState()
    treeState.openNodes(listOf(1, 2, 3))
    Column {
        LazyTree(
            tree = tree,
            modifier = Modifier.fillMaxSize(),
            treeState = treeState,
            onElementClick = {},
            onElementDoubleClick = {},
        ) { element ->
            Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                val icon = when {
                    element.data.startsWith("class") -> "/expui/nodes/classAbstract_dark.svg"
                    element.data.startsWith("subclass") -> "/expui/nodes/class_dark.svg"
                    else -> "/expui/nodes/package_dark.svg"
                }

                when (element) {

                    is Tree.Element.Node -> {
                        Icon(
                            icon,
                            contentDescription = "Namespace",
                            iconClass = javaClass,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(element.data)
                    }

                    is Tree.Element.Leaf -> {

                        Icon(
                            icon,
                            contentDescription = "Namespace",
                            iconClass = javaClass,
                            modifier = Modifier.size(16.dp)
                        )

                        Text(element.data)
                    }
                }
            }
        }
    }
}