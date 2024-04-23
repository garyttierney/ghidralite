import ghidra.program.model.address.Address

// Highlight a range of function pointers to scan them for a call to a given function name.
val functionName = askString("Function name", "What is the name of the function to search for?")

val vtableAddrSet = createAddressSet()
currentSelection.forEach(vtableAddrSet::add)

val virtualFunctionPointers = program.listing.getData(vtableAddrSet, true)
virtualFunctionPointers
    .mapNotNull { it.value as? Address }
    .mapNotNull(::getFunctionAt)
    .forEach {
        // TODO
    }