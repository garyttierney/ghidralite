package io.github.garyttierney.ghidralite.standalone.app.data

class UserData<T : Any>(private var innerValue: T) {
    var isDirty = false
    var value: T
        get() = innerValue
        set(v) {
            innerValue = v
            isDirty = true
        }
}