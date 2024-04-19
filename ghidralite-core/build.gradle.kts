plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
    `ghidralite-benchmark-conventions`
    `java-library`
    alias(libs.plugins.ksp)
}


dependencies {
    implementation(project(":ghidralite-core-ksp"))
    ksp(project(":ghidralite-core-ksp"))

    implementation(libs.kotlinx.coroutines)
    api(libs.intellij.util.base)
    api(libs.intellij.util.text.matching)
    implementation(libs.fastutil)

    compileOnlyApi(platform("ghidra:ghidra"))
    compileOnlyApi("ghidra:DB")
    compileOnlyApi("ghidra:SoftwareModeling")
}
