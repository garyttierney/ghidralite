plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
}

dependencies {
    testImplementation(kotlin("test"))
    implementation(libs.ksp)
    implementation(kotlin("stdlib"))
}
