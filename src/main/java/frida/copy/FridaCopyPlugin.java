package frida.copy;

import jadx.api.JadxDecompiler;
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
import jadx.core.dex.nodes.MethodNode;
import java.util.List;
import java.util.stream.Collectors;

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
        register(gui, decompiler, "Frida: Trace call + stack", ScriptType.TRACE);
        register(gui, decompiler, "Frida: Hook all overloads", ScriptType.OVERLOADS);
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
        if (ref.getAnnType() != ICodeAnnotation.AnnType.METHOD) return false;
        JavaNode node = decompiler.getJavaNodeByRef(ref);
        return node instanceof JavaMethod;
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
                case TRACE:        body = genTrace(varName, rawCls, clsAlias, methodName, aliasName, overloadSig, argList, argNames); break;
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

    // ---- Overloaded scripts ----

    private String buildOverloaded(JavaMethod mth, String rawCls, String clsAlias, String varName,
                                    String name, String alias, ScriptType type) {
        String overloadTypes = mth.getArguments().stream()
                .map(t -> "'" + parseArgType(t) + "'")
                .collect(Collectors.joining(", "));

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

    private static String parseArgType(ArgType type) {
        if (type.isArray()) {
            return jadx.core.codegen.TypeGen.signature(type).replace("/", ".");
        }
        return type.toString();
    }

    private enum ScriptType {
        LOG, RETURN_TRUE, RETURN_FALSE, TRACE, OVERLOADS
    }
}
