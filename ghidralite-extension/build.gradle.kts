plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
    `ghidralite-extension`

    alias(libs.plugins.composeDesktop)
}

ghidra {
    path = rootDir.resolve("ghidra")
}

dependencies {
    compileOnly("ghidra:Base:11.1")
    compileOnly("ghidra:Generic:11.1")
    compileOnly("ghidra:Project:11.1")
    compileOnly("ghidra:SoftwareModeling:11.1")

    implementation(project(":ghidralite-core"))
    implementation(project(":ghidralite-ui"))

    // TODO: should be part of ghidralite-ui API
    implementation(libs.jewel.standalone)
    implementation(compose.desktop.linux_x64)
    implementation(compose.desktop.windows_x64)
    implementation(compose.desktop.common)
}