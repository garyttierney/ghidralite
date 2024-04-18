plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
    alias(libs.plugins.ksp)
    id("me.champeau.jmh") version "0.7.2"
}


dependencies {
    implementation(project(":ghidralite-core-ksp"))
    ksp(project(":ghidralite-core-ksp"))

    implementation(libs.kotlinx.coroutines)
    api(libs.intellij.util.base)
    api(libs.intellij.util.text.matching)
    implementation(libs.fastutil)

    compileOnly(enforcedPlatform("ghidra:ghidra"))
    compileOnly("ghidra:DB")
    compileOnly("ghidra:SoftwareModeling")
}
