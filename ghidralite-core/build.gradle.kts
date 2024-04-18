plugins {
    `ghidralite-kotlin-conventions`
    alias(libs.plugins.ksp)
    id("me.champeau.jmh") version "0.7.2"
}


dependencies {
    implementation(projects.ghidraliteCoreKsp)
    ksp(projects.ghidraliteCoreKsp)

    implementation(libs.kotlinx.coroutines)
    api(libs.intellij.util.base)
    api(libs.intellij.util.text.matching)
    implementation(libs.fastutil)

    compileOnly(platform("ghidra:ghidra"))
    compileOnly("ghidra:DB")
    compileOnly("ghidra:SoftwareModeling")
}
