plugins {
    `ghidralite-conventions`
    `ghidralite-kotlin-conventions`
}

dependencies {
    implementation(libs.ksp)
    implementation(libs.kotlinpoet)
    implementation(libs.kotlinpoet.ksp)
}
