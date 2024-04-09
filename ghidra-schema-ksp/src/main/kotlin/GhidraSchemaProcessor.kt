import com.google.devtools.ksp.processing.*
import com.google.devtools.ksp.symbol.*
import com.google.devtools.ksp.validate
import java.io.OutputStreamWriter

class GhidraSchemaProcessorProvider : SymbolProcessorProvider {
    override fun create(
        environment: SymbolProcessorEnvironment
    ): SymbolProcessor {
        return GhidraSchemaProcessor(environment.codeGenerator, environment.logger)
    }
}

// TODO: big hack
class GhidraSchemaProcessor(
    val codeGenerator: CodeGenerator,
    val logger: KSPLogger
) : SymbolProcessor {
    override fun process(resolver: Resolver): List<KSAnnotated> {
        val symbols = resolver.getSymbolsWithAnnotation("GhidraSchema")
        val ret = symbols.filter { !it.validate() }.toList()
        symbols
            .filter { it is KSClassDeclaration && it.validate() }
            .forEach { it.accept(GhidraSchemaVisitor(), Unit) }
        return ret
    }

    inner class GhidraSchemaVisitor : KSVisitorVoid() {
        override fun visitClassDeclaration(classDeclaration: KSClassDeclaration, data: Unit) {


            val annotation = classDeclaration.annotations.find { it.shortName.asString() == "GhidraSchema" } ?: return
            val fieldsArg = annotation.arguments.find { it.name?.asString() == "fields" } ?: return
            val versionArg = annotation.arguments.find { it.name?.asString() == "version" } ?: return
            val file =
                OutputStreamWriter(
                    codeGenerator.createNewFile(
                        Dependencies(true, classDeclaration.containingFile!!),
                        classDeclaration.packageName.asString(),
                        classDeclaration.simpleName.asString()
                    )
                )
            file.append("package ${classDeclaration.packageName.asString()}\n\n")
            file.append("import db.DBRecord\n\n")

            file.append("class ${classDeclaration.simpleName.asString()}Impl(override val inner: DBRecord) : ${classDeclaration.qualifiedName?.asString()} {\n")

            val fields = fieldsArg.value as? List<KSAnnotation> ?: error("Field isn't an annotation")

            fields.forEachIndexed { index, field ->
                val nameArg = field.arguments.find { it.name?.asString() == "name" } ?: error("No name")
                val typeArg = field.arguments.find { it.name?.asString() == "type" } ?: error("No type")
                val typeString = typeArg.value.toString().split(".").last() // ??
                val type = GhidraType.valueOf(typeString)
                val name = nameArg.value.toString()
                val functionSuffix = when (type) {
                    GhidraType.String -> "String"
                    else -> "${type.name}Value"
                }
                file.appendLine(
                    """
                        override var $name: $type
                            get() = inner.get${functionSuffix}($index)
                            set(v) = inner.set${functionSuffix}($index, v)
                    """.trimIndent()
                )
            }

            file.appendLine("}")
            file.close()
            codeGenerator.associateWithClasses(
                classes = listOf(classDeclaration), classDeclaration.packageName.asString(),
                classDeclaration.simpleName.asString()
            )
        }

        override fun visitFunctionDeclaration(function: KSFunctionDeclaration, data: Unit) {
            val parent = function.parentDeclaration as KSClassDeclaration
            val packageName = parent.containingFile!!.packageName.asString()
            val className = "${parent.simpleName.asString()}Builder"
            val file =
                OutputStreamWriter(
                    codeGenerator.createNewFile(
                        Dependencies(true, function.containingFile!!),
                        packageName,
                        className
                    )
                )
            file.append("package $packageName\n\n")
            file.append("import HELLO\n\n")
            file.append("class $className{\n")
            function.parameters.forEach {
                val name = it.name!!.asString()
                val typeName = StringBuilder(it.type.resolve().declaration.qualifiedName?.asString() ?: "<ERROR>")
                val typeArgs = it.type.element!!.typeArguments
                if (it.type.element!!.typeArguments.isNotEmpty()) {
                    typeName.append("<")
                    typeName.append(
                        typeArgs.map {
                            val type = it.type?.resolve()
                            "${it.variance.label} ${type?.declaration?.qualifiedName?.asString() ?: "ERROR"}" +
                                    if (type?.nullability == Nullability.NULLABLE) "?" else ""
                        }.joinToString(", ")
                    )
                    typeName.append(">")
                }
                file.append("    private var $name: $typeName? = null\n")
                file.append("    internal fun with${name.replaceFirstChar { it.uppercase() }}($name: $typeName): $className {\n")
                file.append("        this.$name = $name\n")
                file.append("        return this\n")
                file.append("    }\n\n")
            }
            file.append("    internal fun build(): ${parent.qualifiedName!!.asString()} {\n")
            file.append("        return ${parent.qualifiedName!!.asString()}(")
            file.append(
                function.parameters.map {
                    "${it.name!!.asString()}!!"
                }.joinToString(", ")
            )
            file.append(")\n")
            file.append("    }\n")
            file.append("}\n")
            file.close()
        }
    }

}