 plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
    alias(libs.plugins.ksp)
    alias(libs.plugins.composeDesktop)
}

dependencies {
    implementation(enforcedPlatform(project(":ghidralite-platform")))
    implementation(project(":ghidralite-core"))
    implementation(project(":ghidralite-ui"))

    implementation(libs.classgraph)
    implementation("org.jetbrains.androidx.lifecycle:lifecycle-viewmodel-compose:2.8.0-dev1593")
    implementation("org.jetbrains.androidx.navigation:navigation-compose:2.8.0-dev1692")

    implementation("ghidra:x86:11.0.3")
    implementation(platform(libs.koin.bom))
    implementation(libs.koin.core)
    implementation(libs.koin.compose)
    implementation(libs.koin.coroutines)
    implementation(libs.intellij.icons)

    implementation(platform(libs.koin.annotations.bom))
    implementation(libs.koin.annotations)
    ksp(libs.koin.ksp.compiler)

    testImplementation(libs.koin.test.junit5)
    implementation(libs.kotlinx.serialization.json)

    implementation(libs.bundles.ghidra.all.modules)
    implementation(libs.jewel.standalone)
    implementation(libs.jewel.decorated.window)
    implementation(libs.filePicker)

    implementation(compose.desktop.linux_x64)
    implementation(compose.desktop.windows_x64)
    implementation(compose.uiTooling)
}

compose.desktop {
    application {
        mainClass = "io.github.garyttierney.ghidralite.standalone.MainKt"
        jvmArgs("-Djava.system.class.loader=ghidra.GhidraClassLoader")

        nativeDistributions {
            modules(
                "java.compiler",
                "java.instrument",
                "java.management",
                "java.naming",
                "java.net.http",
                "java.rmi",
                "java.scripting",
                "java.sql",
                "jdk.unsupported"
            )
        }
    }
}