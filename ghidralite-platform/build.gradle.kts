plugins {
    `ghidralite-conventions`
    `java-platform`
}

dependencies {
    constraints {
        api(project(":ghidralite-core"))
        api(project(":ghidralite-ui"))
    }
}