plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
    alias(libs.plugins.composeDesktop)
}

dependencies {
    implementation(enforcedPlatform(project(":ghidralite-platform")))
    implementation(project(":ghidralite-core"))
    implementation(project(":ghidralite-ui"))
    implementation(libs.bundles.ghidra.all.modules)
    implementation(libs.jewel.standalone)
    implementation(libs.jewel.decorated.window)
}
