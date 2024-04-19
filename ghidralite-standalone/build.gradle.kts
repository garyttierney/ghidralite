plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
    alias(libs.plugins.composeDesktop)
}

dependencies {
    implementation(enforcedPlatform(project(":ghidralite-platform")))
    implementation(project(":ghidralite-core"))
    implementation(project(":ghidralite-ui"))
    implementation("org.jetbrains.androidx.lifecycle:lifecycle-viewmodel-compose:2.8.0-alpha01")
    implementation("org.jetbrains.androidx.navigation:navigation-compose:2.8.0-alpha01")

    implementation(platform(libs.koin.bom))
    implementation(libs.koin.core)
    implementation(libs.koin.compose)
    implementation(libs.koin.coroutines)
    testImplementation(libs.koin.test.junit5)

    implementation(libs.kotlinx.serialization.json)

    implementation(libs.bundles.ghidra.all.modules)
    implementation(libs.jewel.standalone)
    implementation(libs.jewel.decorated.window)

    implementation(compose.desktop.linux_x64)
    implementation(compose.desktop.windows_x64)
}
