package io.github.garyttierney.ghidralite.standalone.app.data

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

class UserData<T : Any>(innerValue: T) {
    var isDirty = false
    var value by mutableStateOf(innerValue)
}