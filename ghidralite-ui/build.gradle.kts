plugins {
    `ghidralite-conventions`
    alias(libs.plugins.composeDesktop)
}

dependencies {
    api(projects.ghidraliteCore)

    api(compose.desktop.windows_x64)
    api(compose.desktop.linux_x64)

    implementation(libs.jewel.standalone)
    implementation(libs.jewel.decorated.window)
    implementation(libs.jetbrains.compose.splitpane)
    implementation(libs.filePicker)
    implementation(libs.intellij.icons)

    implementation(libs.kotlin.reflect)

}