package frida.copy;

import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;
import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.api.plugins.JadxPluginInfoBuilder;
import jadx.api.plugins.gui.JadxGuiContext;
import jadx.api.metadata.ICodeAnnotation;
import jadx.api.metadata.ICodeNodeRef;
import jadx.api.metadata.annotations.VarNode;
import jadx.core.dex.info.MethodInfo;
import jadx.core.dex.instructions.args.ArgType;
import jadx.core.dex.nodes.ClassNode;
import jadx.core.dex.nodes.FieldNode;
import jadx.core.dex.nodes.MethodNode;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.JOptionPane;
import javax.swing.text.JTextComponent;
import java.awt.KeyboardFocusManager;

public class FridaCopyPlugin implements JadxPlugin {

    private static final String ID = "frida-copy";

    @Override
    public JadxPluginInfo getPluginInfo() {
        return JadxPluginInfoBuilder.pluginId(ID)
                .name("Frida Script Copier")
                .description("Right-click any method to copy Frida hook scripts to clipboard")
                .build();
    }

    @Override
    public void init(JadxPluginContext ctx) {
        JadxGuiContext gui = ctx.getGuiContext();
        JadxDecompiler decompiler = ctx.getDecompiler();

        register(gui, decompiler, "Frida: Hook & log args/ret", ScriptType.LOG);
        register(gui, decompiler, "Frida: Return true", ScriptType.RETURN_TRUE);
        register(gui, decompiler, "Frida: Return false", ScriptType.RETURN_FALSE);
        register(gui, decompiler, "Frida: No-op bypass", ScriptType.NOOP);
        register(gui, decompiler, "Frida: Trace call + stack", ScriptType.TRACE);
        register(gui, decompiler, "Frida: Modify arguments", ScriptType.MODIFY_ARGS);
        register(gui, decompiler, "Frida: Conditional breakpoint", ScriptType.CONDITIONAL_BREAKPOINT);
        register(gui, decompiler, "Frida: Dump all fields", ScriptType.DUMP_ALL_FIELDS);
        register(gui, decompiler, "Frida: Hook all overloads", ScriptType.OVERLOADS);

        registerField(gui, decompiler, "Frida: Read field value", ScriptType.READ_FIELD);
        registerField(gui, decompiler, "Frida: Modify field value", ScriptType.MODIFY_FIELD);

        registerKeyBinding(gui, decompiler);
    }

    private void registerField(JadxGuiContext gui, JadxDecompiler decompiler, String label, ScriptType type) {
        gui.addPopupMenuAction(
                label,
                ref -> isField(ref, decompiler),
                null,
                ref -> {
                    JavaNode node = decompiler.getJavaNodeByRef(ref);
                    if (node instanceof jadx.api.JavaField) {
                        gui.copyToClipboard(buildFieldScript((jadx.api.JavaField) node, type));
                    }
                }
        );
    }

    private void register(JadxGuiContext gui, JadxDecompiler decompiler, String label, ScriptType type) {
        gui.addPopupMenuAction(
                label,
                ref -> isMethod(ref, decompiler),
                null,
                ref -> {
                    JavaNode node = decompiler.getJavaNodeByRef(ref);
                    if (node instanceof JavaMethod) {
                        gui.copyToClipboard(buildScript((JavaMethod) node, type));
                    }
                }
        );
    }

    private boolean isMethod(ICodeNodeRef ref, JadxDecompiler decompiler) {
        if (ref == null) return false;
        try {
            JavaNode node = decompiler.getJavaNodeByRef(ref);
            return node instanceof JavaMethod;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isField(ICodeNodeRef ref, JadxDecompiler decompiler) {
        if (ref == null) return false;
        try {
            JavaNode node = decompiler.getJavaNodeByRef(ref);
            return node instanceof jadx.api.JavaField;
        } catch (Exception e) {
            return false;
        }
    }

    private void registerKeyBinding(JadxGuiContext gui, JadxDecompiler decompiler) {
        gui.registerGlobalKeyBinding("control shift G", "Frida: Hook from selection", () -> {
            java.awt.Component focused = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
            if (!(focused instanceof JTextComponent)) {
                JOptionPane.showMessageDialog(gui.getMainFrame(),
                        "Place cursor in the code editor first.",
                        "Frida Script Copier", JOptionPane.WARNING_MESSAGE);
                return;
            }
            JTextComponent editor = (JTextComponent) focused;
            String selected = editor.getSelectedText();
            if (selected == null || selected.trim().isEmpty()) {
                JOptionPane.showMessageDialog(gui.getMainFrame(),
                        "Select a method call like System.exit or checkPin first.",
                        "Frida Script Copier", JOptionPane.WARNING_MESSAGE);
                return;
            }
            selected = selected.trim().replaceAll("[();\\[\\]{}]", "").trim();

            JavaMethod found = findMethodBySelection(decompiler, selected);
            if (found != null) {
                gui.copyToClipboard(buildScript(found, ScriptType.LOG));
                JOptionPane.showMessageDialog(gui.getMainFrame(),
                        "Copied: Hook & log " + found.getDeclaringClass().getName() + "." + found.getName() + "()",
                        "Frida Script Copier", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(gui.getMainFrame(),
                        "Could not resolve method from: \"" + selected + "\"\n\n" +
                        "Tips:\n" +
                        " - Select the full call: System.exit\n" +
                        " - Or just the method name: exit\n" +
                        " - Make sure the class is loaded in jadx",
                        "Frida Script Copier", JOptionPane.WARNING_MESSAGE);
            }
        });
    }

    private JavaMethod findMethodBySelection(JadxDecompiler decompiler, String selection) {
        if (selection.contains(".")) {
            String[] parts = selection.split("\\.", 2);
            String classHint = parts[0];
            String methodHint = parts[1];
            for (JavaClass cls : decompiler.getClasses()) {
                String rawName = cls.getRawName();
                String name = cls.getName();
                if (name.equals(classHint) || rawName.equals(classHint)
                        || name.endsWith("." + classHint) || name.endsWith("$" + classHint)
                        || rawName.endsWith("." + classHint) || rawName.endsWith("/" + classHint)) {
                    for (JavaMethod mth : cls.getMethods()) {
                        if (mth.getName().equals(methodHint)) {
                            return mth;
                        }
                    }
                }
            }
            for (JavaClass cls : decompiler.getClasses()) {
                String rawName = cls.getRawName();
                String name = cls.getName();
                if (rawName.contains(classHint) || name.contains(classHint)) {
                    for (JavaMethod mth : cls.getMethods()) {
                        if (mth.getName().equals(methodHint)) {
                            return mth;
                        }
                    }
                }
            }
        }
        JavaMethod first = null;
        for (JavaClass cls : decompiler.getClasses()) {
            for (JavaMethod mth : cls.getMethods()) {
                if (mth.getName().equals(selection)) {
                    if (first == null) first = mth;
                    else return null;
                }
            }
        }
        return first;
    }

    private boolean isOverloaded(JavaMethod mth) {
        MethodNode mthNode = mth.getMethodNode();
        if (mthNode == null) return false;
        ClassNode cls = mthNode.getDeclaringClass();
        if (cls == null) return false;
        String shortId = mthNode.getMethodInfo().getShortId();
        for (MethodNode other : cls.getMethods()) {
            if (!other.getMethodInfo().getShortId().equals(shortId)
                    && other.getMethodInfo().getName().equals(mth.getName())) {
                return true;
            }
        }
        return false;
    }

    private List<String> getArgNames(JavaMethod mth) {
        MethodNode mthNode = mth.getMethodNode();
        if (mthNode == null) {
            return mth.getArguments().stream()
                    .map(t -> fallbackName(t.toString()))
                    .collect(Collectors.toList());
        }
        List<VarNode> argNodes = mthNode.collectArgNodes();
        if (!argNodes.isEmpty()) {
            return argNodes.stream()
                    .map(VarNode::getName)
                    .collect(Collectors.toList());
        }
        return mth.getArguments().stream()
                .map(t -> fallbackName(t.toString()))
                .collect(Collectors.toList());
    }

    private String fallbackName(String type) {
        if (type == null || type.isEmpty()) return "arg";
        switch (type) {
            case "boolean": return "bool";
            case "byte":    return "byte";
            case "char":    return "ch";
            case "short":   return "sh";
            case "int":     return "i";
            case "long":    return "l";
            case "float":   return "f";
            case "double":  return "d";
            default:
                if (type.startsWith("[")) return "arr";
                int lastDot = type.lastIndexOf('.');
                return lastDot >= 0
                        ? type.substring(lastDot + 1).toLowerCase()
                        : "obj";
        }
    }

    // ---- Script generation ----

    private String buildScript(JavaMethod mth, ScriptType type) {
        MethodNode mthNode = mth.getMethodNode();
        MethodInfo info = mthNode != null ? mthNode.getMethodInfo() : null;
        String rawCls = mth.getDeclaringClass().getRawName();
        String clsAlias = mth.getDeclaringClass().getName();
        String varName = clsAlias.replace("$", "_");
        boolean isConstructor = info != null && info.isConstructor();
        String methodName = isConstructor ? "$init" : info != null ? info.getName() : mth.getName();
        String aliasName = isConstructor ? "$init" : mth.getName();
        boolean overloaded = isOverloaded(mth);

        String overloadSig = "";
        if (overloaded) {
            overloadSig = ".overload(" + mth.getArguments().stream()
                    .map(t -> "'" + parseArgType(t) + "'")
                    .collect(Collectors.joining(", ")) + ")";
        }

        List<String> argNames = getArgNames(mth);
        String argList = String.join(", ", argNames);
        List<String> argTypeStrs = mth.getArguments().stream()
                .map(t -> t.toString())
                .collect(Collectors.toList());

        boolean isVoid = !isConstructor && info != null && info.getReturnType() == ArgType.VOID;

        String body;
        if (type == ScriptType.OVERLOADS || overloaded) {
            body = buildOverloaded(mth, rawCls, clsAlias, varName, methodName, aliasName, type);
        } else {
            switch (type) {
                case LOG:
                    body = isVoid
                            ? genLogVoid(varName, rawCls, clsAlias, methodName, aliasName, overloadSig, argList, argNames)
                            : genLogReturn(varName, rawCls, clsAlias, methodName, aliasName, overloadSig, argList, argNames);
                    break;
                case RETURN_TRUE:  body = genReturn(varName, rawCls, clsAlias, methodName, aliasName, overloadSig, argList, "true"); break;
                case RETURN_FALSE: body = genReturn(varName, rawCls, clsAlias, methodName, aliasName, overloadSig, argList, "false"); break;
                case NOOP:         body = isVoid ? genNoopVoid(varName, rawCls, clsAlias, methodName, overloadSig, argList) : genNoopReturn(varName, rawCls, clsAlias, methodName, overloadSig, argList); break;
                case TRACE:        body = genTrace(varName, rawCls, clsAlias, methodName, aliasName, overloadSig, argList, argNames); break;
                case MODIFY_ARGS:  body = genModifyArgs(varName, rawCls, clsAlias, methodName, aliasName, overloadSig, argList, argNames, argTypeStrs); break;
                case CONDITIONAL_BREAKPOINT: body = genConditionalBreakpoint(varName, rawCls, clsAlias, methodName, aliasName, overloadSig, argList, argNames); break;
                case DUMP_ALL_FIELDS: body = genDumpAllFields(varName, rawCls, clsAlias, methodName, aliasName, overloadSig, argList, argNames); break;
                default: body = "";
            }
        }
        return "Java.perform(function() {\n" + body + "});\n";
    }

    // ---- Non-overloaded scripts ----

    private String genLogReturn(String var, String rawCls, String clsAlias, String name, String alias,
                                 String overloadSig, String argList, List<String> argNames) {
        String logCall = buildLogCall(alias, name, argNames);
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "%s[\"%s\"]%s.implementation = function (%s) {\n" +
            "  send(`%s.%s is called: %s`);\n" +
            "  var ret = this[\"%s\"](%s);\n" +
            "  send(`%s.%s result=${ret}`);\n" +
            "  return ret;\n" +
            "};\n",
            var, rawCls,
            var, name, overloadSig, argList,
            clsAlias, name, logCall,
            name, argList,
            clsAlias, name
        );
    }

    private String genLogVoid(String var, String rawCls, String clsAlias, String name, String alias,
                               String overloadSig, String argList, List<String> argNames) {
        String logCall = buildLogCall(alias, name, argNames);
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "%s[\"%s\"]%s.implementation = function (%s) {\n" +
            "  send(`%s.%s is called: %s`);\n" +
            "  this[\"%s\"](%s);\n" +
            "};\n",
            var, rawCls,
            var, name, overloadSig, argList,
            clsAlias, name, logCall,
            name, argList
        );
    }

    private String genReturn(String var, String rawCls, String clsAlias, String name, String alias,
                              String overloadSig, String argList, String retVal) {
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "%s[\"%s\"]%s.implementation = function (%s) {\n" +
            "  send(`%s.%s => %s bypass`);\n" +
            "  return %s;\n" +
            "};\n",
            var, rawCls,
            var, name, overloadSig, argList,
            clsAlias, name, retVal,
            retVal
        );
    }

    private String genNoopReturn(String var, String rawCls, String clsAlias, String name,
                                  String overloadSig, String argList) {
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "%s[\"%s\"]%s.implementation = function (%s) {\n" +
            "  send(`[bypass] %s.%s no-op`);\n" +
            "};\n",
            var, rawCls,
            var, name, overloadSig, argList,
            clsAlias, name
        );
    }

    private String genNoopVoid(String var, String rawCls, String clsAlias, String name,
                                String overloadSig, String argList) {
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "%s[\"%s\"]%s.implementation = function (%s) {\n" +
            "  send(`[bypass] %s.%s no-op`);\n" +
            "};\n",
            var, rawCls,
            var, name, overloadSig, argList,
            clsAlias, name
        );
    }

    private String genTrace(String var, String rawCls, String clsAlias, String name, String alias,
                             String overloadSig, String argList, List<String> argNames) {
        String logCall = buildLogCall(alias, name, argNames);
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "%s[\"%s\"]%s.implementation = function (%s) {\n" +
            "  send(`%s.%s is called: %s`);\n" +
            "  send(Java.use(\"android.util.Log\").getStackTraceString(\n" +
            "    Java.use(\"java.lang.Throwable\").$new()));\n" +
            "  return this[\"%s\"](%s);\n" +
            "};\n",
            var, rawCls,
            var, name, overloadSig, argList,
            clsAlias, name, logCall,
            name, argList
        );
    }

    private String genModifyArgs(String var, String rawCls, String clsAlias, String name, String alias,
                                  String overloadSig, String argList, List<String> argNames,
                                  List<String> argTypes) {
        StringBuilder lines = new StringBuilder();
        lines.append(String.format("var %s = Java.use(\"%s\");\n", var, rawCls));
        lines.append(String.format("%s[\"%s\"]%s.implementation = function (%s) {\n",
                var, name, overloadSig, argList));
        lines.append(String.format("  send(`%s.%s is called: %s`);\n",
                clsAlias, name, buildLogCall(alias, name, argNames)));

        for (int i = 0; i < argNames.size(); i++) {
            String n = argNames.get(i);
            String placeholder = argPlaceholder(argTypes.get(i));
            lines.append(String.format("  %s = %s;  // <-- EDIT THIS VALUE\n", n, placeholder));
        }

        for (int i = 0; i < argNames.size(); i++) {
            String n = argNames.get(i);
            lines.append(String.format("  send(\"[modify] %s=\" + %s);\n", n, n));
        }

        String callArgs = String.join(", ", argNames);
        if (argNames.isEmpty()) {
            lines.append(String.format("  var ret = this[\"%s\"]();\n", name));
        } else {
            lines.append(String.format("  var ret = this[\"%s\"](%s);\n", name, callArgs));
        }
        lines.append(String.format("  send(\"%s.%s result=\" + ret);\n", clsAlias, name));
        lines.append("  return ret;\n");
        lines.append("};\n");
        return lines.toString();
    }

    private String genConditionalBreakpoint(String var, String rawCls, String clsAlias, String name,
                                             String alias, String overloadSig, String argList,
                                             List<String> argNames) {
        StringBuilder lines = new StringBuilder();
        lines.append(String.format("var %s = Java.use(\"%s\");\n", var, rawCls));
        lines.append(String.format("%s[\"%s\"]%s.implementation = function (%s) {\n",
                var, name, overloadSig, argList));
        lines.append(String.format("  send(`%s.%s is called: %s`);\n",
                clsAlias, name, buildLogCall(alias, name, argNames)));
        lines.append("  // EDIT YOUR CONDITION BELOW (example: arg == \"value\")\n");
        lines.append("  if (true) {  // <-- change this condition\n");
        lines.append(String.format("    send(\"========================================\");\n"));
        lines.append(String.format("    send(\"  [BREAKPOINT HIT] %s.%s\", );\n", clsAlias, name));
        for (String n : argNames) {
            lines.append(String.format("    send(\"    %s=\" + %s);\n", n, n));
        }
        lines.append(String.format("    send(\"========================================\");\n"));
        lines.append("    Java.use(\"java.lang.Thread\").sleep(5000);\n");
        lines.append("    send(\"  [RESUMING]\");\n");
        lines.append("  }\n");
        lines.append("  // EDIT YOUR CONDITION ABOVE\n");

        String callArgs = String.join(", ", argNames);
        if (argNames.isEmpty()) {
            lines.append(String.format("  var ret = this[\"%s\"]();\n", name));
        } else {
            lines.append(String.format("  var ret = this[\"%s\"](%s);\n", name, callArgs));
        }
        lines.append(String.format("  send(\"%s.%s result=\" + ret);\n", clsAlias, name));
        lines.append("  return ret;\n");
        lines.append("};\n");
        return lines.toString();
    }

    private String genDumpAllFields(String var, String rawCls, String clsAlias, String name, String alias,
                                     String overloadSig, String argList, List<String> argNames) {
        String callArgs = String.join(", ", argNames);
        String call = argNames.isEmpty()
                ? String.format("this[\"%s\"]()", name)
                : String.format("this[\"%s\"](%s)", name, callArgs);

        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "%s[\"%s\"]%s.implementation = function (%s) {\n" +
            "  send(\"========================================\");\n" +
            "  send(\"  [DUMP] %s.%s called — dumping all fields\");\n" +
            "  var fields = this.getClass().getDeclaredFields();\n" +
            "  for (var i = 0; i < fields.length; i++) {\n" +
            "    fields[i].setAccessible(true);\n" +
            "    var fname = fields[i].getName();\n" +
            "    try {\n" +
            "      var fval = fields[i].get(this);\n" +
            "      send(\"    \" + fname + \" = \" + fval);\n" +
            "    } catch(e) {\n" +
            "      send(\"    \" + fname + \" = <error: \" + e + \">\");\n" +
            "    }\n" +
            "  }\n" +
            "  send(\"========================================\");\n" +
            "  var ret = %s;\n" +
            "  send(\"%s.%s result=\" + ret);\n" +
            "  return ret;\n" +
            "};\n",
            var, rawCls,
            var, name, overloadSig, argList,
            clsAlias, name,
            call,
            clsAlias, name
        );
    }

    // ---- Field scripts ----

    private String buildFieldScript(jadx.api.JavaField field, ScriptType type) {
        String rawCls = field.getDeclaringClass().getRawName();
        String clsAlias = field.getDeclaringClass().getName();
        String varName = clsAlias.replace("$", "_");
        String fieldName = field.getRawName();
        FieldNode fieldNode = field.getFieldNode();
        boolean isStatic = fieldNode != null && fieldNode.isStatic();
        String fieldType = field.getType().toString();
        String placeholder = argPlaceholder(fieldType);

        switch (type) {
            case READ_FIELD:
                return isStatic
                        ? genReadStaticField(varName, rawCls, clsAlias, fieldName)
                        : genReadInstanceField(varName, rawCls, clsAlias, fieldName);
            case MODIFY_FIELD:
                return isStatic
                        ? genModifyStaticField(varName, rawCls, clsAlias, fieldName, placeholder)
                        : genModifyInstanceField(varName, rawCls, clsAlias, fieldName, placeholder);
            default:
                return "";
        }
    }

    private String genReadStaticField(String var, String rawCls, String clsAlias, String fieldName) {
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "send(\"[field] %s.%s = \" + %s.%s.value);\n",
            var, rawCls,
            clsAlias, fieldName,
            var, fieldName
        );
    }

    private String genReadInstanceField(String var, String rawCls, String clsAlias, String fieldName) {
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "Java.choose(\"%s\", {\n" +
            "  onMatch: function(instance) {\n" +
            "    send(\"[field] instance.%s = \" + instance.%s.value);\n" +
            "  },\n" +
            "  onComplete: function() {}\n" +
            "});\n",
            var, rawCls,
            rawCls,
            fieldName, fieldName
        );
    }

    private String genModifyStaticField(String var, String rawCls, String clsAlias, String fieldName, String placeholder) {
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "%s.%s.value = %s;  // <-- EDIT THIS VALUE\n" +
            "send(\"[field] %s.%s = \" + %s.%s.value);\n",
            var, rawCls,
            var, fieldName, placeholder,
            clsAlias, fieldName,
            var, fieldName
        );
    }

    private String genModifyInstanceField(String var, String rawCls, String clsAlias, String fieldName, String placeholder) {
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "Java.choose(\"%s\", {\n" +
            "  onMatch: function(instance) {\n" +
            "    instance.%s.value = %s;  // <-- EDIT THIS VALUE\n" +
            "    send(\"[field] instance.%s = \" + instance.%s.value);\n" +
            "  },\n" +
            "  onComplete: function() {}\n" +
            "});\n",
            var, rawCls,
            rawCls,
            fieldName, placeholder,
            fieldName, fieldName
        );
    }

    // ---- Overloaded scripts ----

    private String buildOverloaded(JavaMethod mth, String rawCls, String clsAlias, String varName,
                                    String name, String alias, ScriptType type) {
        switch (type) {
            case LOG:
                return String.format(
                    "var %s = Java.use(\"%s\");\n" +
                    "%s[\"%s\"].overloads.forEach(function(overload) {\n" +
                    "  overload.implementation = function() {\n" +
                    "    var args = Array.prototype.slice.call(arguments);\n" +
                    "    send(`%s.%s called with ${JSON.stringify(args)}`);\n" +
                    "    var ret = overload.apply(this, arguments);\n" +
                    "    send(`%s.%s result=${ret}`);\n" +
                    "    return ret;\n" +
                    "  };\n" +
                    "});\n",
                    varName, rawCls,
                    varName, name,
                    clsAlias, name,
                    clsAlias, name
                );
            case RETURN_TRUE:
                return overloadedReturn(varName, rawCls, clsAlias, name, "true");
            case RETURN_FALSE:
                return overloadedReturn(varName, rawCls, clsAlias, name, "false");
            case TRACE:
                return String.format(
                    "var %s = Java.use(\"%s\");\n" +
                    "%s[\"%s\"].overloads.forEach(function(overload) {\n" +
                    "  overload.implementation = function() {\n" +
                    "    send(`%s.%s called (overloaded)`);\n" +
                    "    send(Java.use(\"android.util.Log\").getStackTraceString(\n" +
                    "      Java.use(\"java.lang.Throwable\").$new()));\n" +
                    "    return overload.apply(this, arguments);\n" +
                    "  };\n" +
                    "});\n",
                    varName, rawCls,
                    varName, name,
                    clsAlias, name
                );
            case MODIFY_ARGS:
                return String.format(
                    "var %s = Java.use(\"%s\");\n" +
                    "%s[\"%s\"].overloads.forEach(function(overload) {\n" +
                    "  overload.implementation = function() {\n" +
                    "    var args = Array.prototype.slice.call(arguments);\n" +
                    "    send(`%s.%s called with ${JSON.stringify(args)}`);\n" +
                    "    // EDIT args ARRAY VALUES BELOW\n" +
                    "    // args[0] = \"new_value\";\n" +
                    "    // EDIT args ARRAY VALUES ABOVE\n" +
                    "    send(`[modify] args=${JSON.stringify(args)}`);\n" +
                    "    var ret = overload.apply(this, args);\n" +
                    "    send(`%s.%s result=${ret}`);\n" +
                    "    return ret;\n" +
                    "  };\n" +
                    "});\n",
                    varName, rawCls,
                    varName, name,
                    clsAlias, name,
                    clsAlias, name
                );
            case CONDITIONAL_BREAKPOINT:
                return String.format(
                    "var %s = Java.use(\"%s\");\n" +
                    "%s[\"%s\"].overloads.forEach(function(overload) {\n" +
                    "  overload.implementation = function() {\n" +
                    "    var args = Array.prototype.slice.call(arguments);\n" +
                    "    send(`%s.%s called with ${JSON.stringify(args)}`);\n" +
                    "    // EDIT YOUR CONDITION BELOW\n" +
                    "    if (true) {  // <-- change this condition\n" +
                    "      send(\"========================================\");\n" +
                    "      send(\"  [BREAKPOINT HIT] %s.%s (overloaded)\");\n" +
                    "      send(\"    args=\" + JSON.stringify(args));\n" +
                    "      send(\"========================================\");\n" +
                    "      Java.use(\"java.lang.Thread\").sleep(5000);\n" +
                    "      send(\"  [RESUMING]\");\n" +
                    "    }\n" +
                    "    // EDIT YOUR CONDITION ABOVE\n" +
                    "    var ret = overload.apply(this, arguments);\n" +
                    "    send(`%s.%s result=${ret}`);\n" +
                    "    return ret;\n" +
                    "  };\n" +
                    "});\n",
                    varName, rawCls,
                    varName, name,
                    clsAlias, name,
                    clsAlias, name,
                    clsAlias, name
                );
            default:
                return "";
        }
    }

    private String overloadedReturn(String var, String rawCls, String clsAlias, String name, String retVal) {
        return String.format(
            "var %s = Java.use(\"%s\");\n" +
            "%s[\"%s\"].overloads.forEach(function(overload) {\n" +
            "  overload.implementation = function() {\n" +
            "    send(`%s.%s => %s bypass (overloaded)`);\n" +
            "    return %s;\n" +
            "  };\n" +
            "});\n",
            var, rawCls,
            var, name,
            clsAlias, name, retVal,
            retVal
        );
    }

    // ---- Helpers ----

    private static String buildLogCall(String clsAlias, String name, List<String> argNames) {
        if (argNames.isEmpty()) return "";
        return argNames.stream()
                .map(n -> n + "=${" + n + "}")
                .collect(Collectors.joining(", "));
    }

    private static String argPlaceholder(String type) {
        if (type == null) return "CHANGE_ME";
        switch (type) {
            case "boolean": return "true";
            case "byte":
            case "char":
            case "short":
            case "int":
            case "long":    return "1";
            case "float":
            case "double":  return "1.0";
            case "java.lang.String": return "\"CHANGE_ME\"";
            default:        return "null";
        }
    }

    private static String parseArgType(ArgType type) {
        if (type.isArray()) {
            return jadx.core.codegen.TypeGen.signature(type).replace("/", ".");
        }
        return type.toString();
    }

    private enum ScriptType {
        LOG, RETURN_TRUE, RETURN_FALSE, NOOP, TRACE, OVERLOADS, MODIFY_ARGS, CONDITIONAL_BREAKPOINT,
        DUMP_ALL_FIELDS, READ_FIELD, MODIFY_FIELD
    }
}
