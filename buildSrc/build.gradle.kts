plugins {
    `kotlin-dsl`
}

kotlin {
    sourceSets {
        all {
            languageSettings {
                optIn("kotlinx.serialization.ExperimentalSerializationApi")
            }
        }
    }
}

dependencies {
    implementation(libs.kotlin.gradlePlugin)
    implementation(libs.kotlin.serialization.gradlePlugin)
    implementation(libs.idea.gradlePlugin)
    implementation(libs.kover.gradlePlugin)
    implementation(libs.detekt.gradlePlugin)
    implementation(libs.jmh.gradlePlugin)

    // Enables using type-safe accessors to reference plugins from the [plugins] block defined in
    // version catalogs.
    // Context: https://github.com/gradle/gradle/issues/15383#issuecomment-779893192
    implementation(files(libs.javaClass.superclass.protectionDomain.codeSource.location))
}