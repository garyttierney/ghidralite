plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
}

dependencies {
    implementation(kotlin("scripting-common"))
    implementation(kotlin("scripting-jvm"))
    implementation(kotlin("scripting-jvm-host"))
    implementation(kotlin("scripting-dependencies"))
    implementation(kotlin("scripting-dependencies-maven"))

    implementation("ghidra:Base")
    implementation(libs.kotlinx.coroutines)
}